/**
 * @file
 * @brief FenceLock AES-256-GCM encrypt/decrypt console utility with locked memory and guard pages.
 * 
 *                             _____
 *                            |  ___|__ _ __   ___ ___
 *                            | |_ / _ \ '_ \ / __/ _ \
 *                            |  _|  __/ | | | (_|  __/
 *                            |_|  \___|_| |_|\___\___|
 *                       _       _                   _
 *                     ('<     ('<                 >')
 *                     (^)     (^)                 (^)
 *                     |m/|   |\m|   |\/|   |\/|   |m/|   |\/|
 *                     |  | _ |  | _ |  | _ |  | _ |  | _ |  |
 *                     |  |(@)|  |<.>|  |{o}|  |<.>|  |(@)|  |
 *                   __|__|_|_|__|_|_|__|_|_|__|_|_|__|_|_|__|__
 *                  |___::_____::_____::_____::_____::_____::___|
 *                     |  | | |  | | |  | | |  | | |  | | |  |
 *                     |  |\|/|  |\|/|  |\|/|  |\|/|  |\|/|  |ldb
 *                WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
 * 
 * This program encrypts and decrypts files and inline text using AES-256-GCM. Keys are derived via
 * scrypt with a 16-byte random salt. Ciphertext packets are framed as:
 * [ "FEN$" | 16B salt | 12B iv | ciphertext | 16B tag ].
 *
 * Memory that may contain secrets is allocated with a custom allocator that:
 *  - Reserves a region with PAGE_NOACCESS guard pages on both sides,
 *  - Commits a middle section holding a page-aligned header + payload,
 *  - Lock the committed pages via VirtualLock,
 *  - Appends a 0xD0 canary to detect overruns,
 *  - Scrubs memory on deallocation.
 *
 * The process attempts to enable several Windows mitigations (no dynamic code, strict handle checks,
 * signed-image loading preferences, etc.) and elevates the 'SeLockMemoryPrivilege' when possible.
 *
 * @note Requires OpenSSL 3.x.
 */

#define NOMINMAX

#include <windows.h>
#include <winnt.h>
#include <wincred.h>
#include <conio.h>

#ifndef _WIN32
#error "Platform not supported: This source targets Windows APIs."
#endif

#ifdef _MSC_VER
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")
#endif

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <limits>
#include <cctype>
#include <algorithm>
#include <cstdio>
#include <utility>
#include <fstream>
#include <thread>
#include <new>
#include <memory>
#include <iterator>
#include <functional>
#include <filesystem>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <string_view>
#include <cstddef>
#include <span>
#include <ranges>
#include <concepts>
#include <cassert>
#include <future>

#include <heapapi.h>
#include <shellapi.h>
#include <processthreadsapi.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/**
 * @namespace fenc
 * @brief Internal implementation namespace for FenceLock.
 *
 * Houses secure allocators, string wrappers, utility helpers (hex, file, clipboard),
 * and crypto primitives used by the top-level console workflow.
 */
namespace fenc {
    /**
     * @namespace fenc::cfg
     * @brief Cryptographic and framing constants.
     *
     * @var SALT_LEN 16-byte scrypt salt.
     * @var KEY_LEN  32-byte AES-256 key length.
     * @var IV_LEN   12-byte GCM nonce length.
     * @var TAG_LEN  16-byte GCM authentication tag length.
     * @var FILE_CHUNK Reserved for future streaming I/O (1 MiB).
     * @var AAD_HDR  ASCII AAD prefix ("FEN$") included/authenticated but not encrypted.
     * @var AAD_LEN  Length of @ref AAD_HDR.
     */
    namespace cfg {
        static constexpr size_t SALT_LEN = 16;
        static constexpr size_t KEY_LEN = 32;
        static constexpr size_t IV_LEN = 12;
        static constexpr size_t TAG_LEN = 16;
        static constexpr size_t FILE_CHUNK = 1 << 20;
        static constexpr char   AAD_HDR[] = "FEN$";
        static constexpr size_t AAD_LEN = sizeof(AAD_HDR) - 1;
    }

    /**
     * @brief Concept for byte-addressable element types.
     * @tparam T Type whose decayed form must be 'unsigned char', 'char', or 'std::byte'.
     */
    template<class T>
    concept byte_like = std::same_as<std::remove_cv_t<T>, unsigned char> ||
        std::same_as<std::remove_cv_t<T>, char> ||
#if __cplusplus >= 201703L
        std::same_as<std::remove_cv_t<T>, std::byte>;
#else
        false;
#endif

    /**
     * @brief Round a value up to the next multiple of an alignment.
     * @param v Value to align.
     * @param a Alignment (power of two).
     * @return 'v' rounded up to 'a'.
     */
    static inline size_t align_up(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }

    // Canary & header integrity
    static constexpr uint32_t kMagic = 0x53524950u;
    static constexpr uint32_t kVersion = 1u;
    static constexpr size_t   kCanaryBytes = 32; // Multiple of 16

    /**
     * @brief Per-allocation metadata stored at the start of the committed region.
     *
     * Layout (per allocation):
     * [ guard page | committed: header (page-aligned) + payload (usable) + canary + slack | guard page ]
     *
     * The header is page-aligned to simplify protection changes and to survive accidental
     * buffer overreads into the header region.
     *
     * @warning The header itself is scrubbed before release. Only 'magic'/'version'
     * are consulted during deallocation for sanity.
     */
    struct locked_header {
        void* base;         // Start of reserved region
        size_t total;       // Total reserved bytes (guard + middle + guard)
        size_t middleSize;  // Committed bytes (no guards)
        size_t usable;      // Requested payload bytes (BYTES)
        size_t headerSize;  // Padded header size used
        size_t payloadSpan; // Committed payload span (usable + canary + slack)
        uint32_t magic;     // Integrity
        uint32_t version;   // Version
    };

    /**
     * @brief Reconstruct allocation header from a payload pointer.
     * @tparam T Element type of the payload.
     * @param payload Pointer previously returned by the locked allocator.
     * @return Pointer to the header for the surrounding reserved region.
     * @pre 'payload' must originate from @ref locked_allocator.
     */
    template<class T>
    inline locked_header* header_from_payload(const T* payload) {
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        SIZE_T page = si.dwPageSize ? si.dwPageSize : 4096;
        SIZE_T headerSize = align_up(sizeof(locked_header), page);
        return reinterpret_cast<locked_header*>((BYTE*)const_cast<T*>(payload) - headerSize);
    }

    /**
     * @brief Secure allocator with guard pages and best-effort page locking.
     * @tparam T element type.
     *
     * Allocations:
     *  - Reserve '[guard | middle | guard]' via 'VirtualAlloc'.
     *  - Commit the middle region, page-align the header, and place a 0xD0 canary after the usable span.
     *  - Best-effort 'VirtualLock' the committed pages.
     *
     * Deallocation:
     *  - Restores RW temporarily to check canary and to wipe the usable span.
     *  - Emits a debug warning on canary mismatch (unless already wiped).
     *  - Unlocks and releases the whole reserved region.
     *
     * @note Propagates neither state nor equality semantics; instances are interchangeable.
     */
    template <class T>
    struct locked_allocator {
        using value_type = T;

        locked_allocator() noexcept {}
        template<class U> locked_allocator(const locked_allocator<U>&) noexcept {}

        /**
         * @brief Allocate 'n' objects in a locked, guarded region.
         * @param n Number of elements (treated as 1 if 0).
         * @return Pointer to the usable payload.
         * @throws std::bad_alloc on reservation/commit failure.
         * @post The tail canary bytes are set to 0xD0.
         */
        T* allocate(std::size_t n) {
            if (n == 0) n = 1;
            SIZE_T needBytes = n * sizeof(T);

            SYSTEM_INFO si{}; GetSystemInfo(&si);
            SIZE_T page = si.dwPageSize ? si.dwPageSize : 4096;
            SIZE_T headerSize = align_up(sizeof(locked_header), page);
            SIZE_T afterHeader = headerSize + needBytes + kCanaryBytes;
            SIZE_T middleNeed = align_up(afterHeader, page);
            SIZE_T total = middleNeed + 2 * page;

            BYTE* base = (BYTE*)VirtualAlloc(nullptr, total, MEM_RESERVE, PAGE_NOACCESS);
            if (!base) throw std::bad_alloc();

            BYTE* middle = (BYTE*)VirtualAlloc(base + page, middleNeed, MEM_COMMIT, PAGE_READWRITE);
            if (!middle) { VirtualFree(base, 0, MEM_RELEASE); throw std::bad_alloc(); }

            (void)VirtualLock(middle, middleNeed); // Best-effort

            auto* hdr = reinterpret_cast<locked_header*>(middle);
            hdr->base = base;
            hdr->total = total;
            hdr->middleSize = middleNeed;
            hdr->usable = needBytes;
            hdr->headerSize = headerSize;
            hdr->payloadSpan = middleNeed - headerSize; // Includes canary + slack
            hdr->magic = kMagic;
            hdr->version = kVersion;

            BYTE* payload = middle + headerSize;

            // Tail canary
            memset(payload + needBytes, 0xD0, (std::min)(kCanaryBytes, hdr->payloadSpan - hdr->usable));
            return reinterpret_cast<T*>(payload);
        }

        /**
         * @brief Deallocate and securely wipe a prior allocation.
         * @param p Payload pointer returned by @ref allocate.
         *
         * Performs header sanity checks, verifies the tail canary (unless already zeroed),
         * temporarily opens RW protection to wipe the payload span, then unlocks and
         * releases the reserved region.
         */
        void deallocate(T* p, std::size_t) noexcept {
            if (!p) return;

            auto* hdr = header_from_payload(p);
            BYTE* bytes = reinterpret_cast<BYTE*>(p);

            // Header sanity
            if (hdr->magic != kMagic || hdr->version != kVersion) {
#ifdef _MSC_VER
                __fastfail(1);
#else
                std::terminate();
#endif
            }

            // Save fields BEFORE any wiping
            void* base = hdr->base;
            SIZE_T middleSize = hdr->middleSize;
            SIZE_T payloadSpan = hdr->payloadSpan;
            SIZE_T usable = hdr->usable;

            // Ensure readable to check canary
            DWORD oldProt{}, dummy{};
            (void)VirtualProtect(bytes, payloadSpan, PAGE_READWRITE, &oldProt);

            const size_t canary_span = (std::min)(kCanaryBytes, payloadSpan - usable);

            bool canary_ok = true;
            for (size_t i = 0; i < canary_span; ++i) {
                if (bytes[usable + i] != (BYTE)0xD0) { canary_ok = false; break; }
            }

            bool looks_wiped = true;
            for (size_t i = 0; i < usable + canary_span; ++i) {
                if (bytes[i] != 0) { looks_wiped = false; break; }
            }

            if (payloadSpan) SecureZeroMemory(bytes, payloadSpan);
            (void)VirtualProtect(bytes, payloadSpan, oldProt, &dummy);

#if defined(_DEBUG)
            if (!canary_ok && !looks_wiped) {
#ifdef _MSC_VER
                __fastfail(2);
#else
                std::terminate();
#endif
            }
#else
            if (!canary_ok && !looks_wiped) {
                OutputDebugStringA("[FenceLock] WARN: canary mismatch on free (not wiped)\n");
            }
#endif

            // Now it's safe to wipe the header structure itself.
            SecureZeroMemory(hdr, sizeof(locked_header));

            // Use saved values
            if (middleSize) (void)VirtualUnlock((LPVOID)((BYTE*)hdr), middleSize);
            if (base)       (void)VirtualFree(base, 0, MEM_RELEASE);
        }

        template<class U> struct rebind { using other = locked_allocator<U>; };
    };

    /**
     * @brief Redacted stream insertion for secure strings.
     * @return A placeholder indicating byte length; never prints secret data.
     */
    template<class T, class U>
    inline bool operator==(const locked_allocator<T>&, const locked_allocator<U>&) { return true; }
    template<class T, class U>
    inline bool operator!=(const locked_allocator<T>&, const locked_allocator<U>&) { return false; }

    /**
     * @brief Switch the payload protection to 'PAGE_NOACCESS'.
     * @tparam T payload element type.
     * @param p Pointer into a locked allocation (payload).
     * @note No-op on null.
     */
    template<class T>
    inline void protect_noaccess(const T* p) {
        if (!p) return;
        auto* hdr = header_from_payload(p);
        DWORD oldProt;
        (void)VirtualProtect((LPVOID)p, hdr->payloadSpan, PAGE_NOACCESS, &oldProt);
    }

    /**
     * @brief Switch the payload protection to 'PAGE_READWRITE'.
     * @tparam T payload element type.
     * @param p Pointer into a locked allocation (payload).
     * @note No-op on null.
     */
    template<class T>
    inline void protect_readwrite(const T* p) {
        if (!p) return;
        auto* hdr = header_from_payload(p);
        DWORD oldProt;
        (void)VirtualProtect((LPVOID)p, hdr->payloadSpan, PAGE_READWRITE, &oldProt);
    }

    /**
     * @brief Narrow secure string using @ref locked_allocator<char>.
     *
     * Semantics mirror a minimal 'std::string' subset (mutable contiguous storage),
     * but memory is allocated in a locked, guarded region and scrubbed on 'clear()'/destruction.
     *
     * @warning 'c_str()' appends a '\0' if not present. Avoid keeping raw pointers
     * across mutating operations. Use @ref view() when possible.
     */
    template <class A = locked_allocator<char>>
    struct secure_string {
        std::vector<char, A> s;

        secure_string() = default;
        secure_string(const secure_string&) = delete;
        secure_string& operator=(const secure_string&) = delete;
        secure_string(secure_string&& o) noexcept : s(std::move(o.s)) {}
        secure_string& operator=(secure_string&& o) noexcept {
            if (this != &o) { clear(); s = std::move(o.s); }
            return *this;
        }
        ~secure_string() { clear(); }

        void   push_back(char c) { s.push_back(c); }
        void   pop_back() { if (!s.empty()) s.pop_back(); }
        bool   empty() const { return s.empty(); }
        size_t size()  const { return s.size(); }
        char*  data() { return s.data(); }
        const char*      data() const { return s.data(); }
        std::string_view view() const noexcept { return { s.data(), s.size() }; }

        const char* c_str() {
            if (s.empty() || s.back() != '\0') s.push_back('\0');
            return s.data();
        }

        void clear() {
            if (!s.empty()) {
                fenc::protect_readwrite(s.data());
                SecureZeroMemory(s.data(), s.size());
                s.clear();
                std::vector<char, A>().swap(s);
            }
            else {
                // Even if empty, there could still be capacity with a protected buffer.
                if (s.capacity() > 0 && s.data()) {
                    fenc::protect_readwrite(s.data());
                    s.clear();
                    std::vector<char, A>().swap(s);
                }
            }
        }

        std::string str_copy() const { return std::string(s.data(), s.data() + s.size()); }
    };

    /**
    * @brief Generic secure string for arbitrary code unit types (e.g., 'wchar_t', 'char16_t').
    * @tparam CharT Code unit type.
    * @tparam A Locked allocator type (defaults to @ref locked_allocator<CharT>).
    *
    * Provides contiguous storage with secure wiping and guarded allocation identical
    * to @ref secure_string, adapted for wide/UTF code units.
    */
    template <class CharT, class A = locked_allocator<CharT>>
    struct basic_secure_string {
        std::vector<CharT, A> s;

        basic_secure_string() = default;
        basic_secure_string(const basic_secure_string&) = delete;
        basic_secure_string& operator=(const basic_secure_string&) = delete;
        basic_secure_string(basic_secure_string&& o) noexcept : s(std::move(o.s)) {}
        basic_secure_string& operator=(basic_secure_string&& o) noexcept {
            if (this != &o) { clear(); s = std::move(o.s); }
            return *this;
        }
        ~basic_secure_string() { clear(); }

        void   push_back(CharT c) { s.push_back(c); }
        void   pop_back() { if (!s.empty()) s.pop_back(); }
        bool   empty() const { return s.empty(); }
        size_t size()  const { return s.size(); }
        CharT* data() { return s.data(); }
        const CharT*                  data() const { return s.data(); }
        std::basic_string_view<CharT> view() const noexcept { return { s.data(), s.size() }; }

        const CharT* c_str() {
            if (s.empty() || s.back() != CharT{}) s.push_back(CharT{});
            return s.data();
        }

        void clear() {
            if (!s.empty()) {
                fenc::protect_readwrite(s.data());
                SecureZeroMemory(s.data(), s.size() * sizeof(CharT));
                s.clear();
                std::vector<CharT, A>().swap(s);
            }
            else {
                if (s.capacity() > 0 && s.data()) {
                    fenc::protect_readwrite(s.data());
                    s.clear();
                    std::vector<CharT, A>().swap(s);
                }
            }
        }

        std::basic_string<CharT> str_copy() const { return std::basic_string<CharT>(s.data(), s.data() + s.size()); }
    };

    /**
     * @brief RAII helper to temporarily set a locked payload span to RW.
     *
     * Captures the prior protection of the payload span and restores it on scope exit.
     * Safe to use on null pointers; in that case it is a no-op.
     */
    template<class T>
    struct RWGuard {
        const T* p{};
        DWORD oldProt{};
        bool changed{ false };
        explicit RWGuard(const T* ptr) : p(ptr) {
            if (!p) return;
            auto* hdr = header_from_payload(p);
            changed = !!VirtualProtect((LPVOID)p, hdr->payloadSpan, PAGE_READWRITE, &oldProt);
        }
        ~RWGuard() {
            if (!p || !changed) return;
            auto* hdr = header_from_payload(p);
            DWORD tmp;
            (void)VirtualProtect((LPVOID)p, hdr->payloadSpan, oldProt, &tmp);
        }
    };

    /**
     * @brief Constant-time byte comparison.
     * @param a First buffer.
     * @param b Second buffer.
     * @param n Number of bytes.
     * @return 'true' if equal, else 'false'.
     * @note Branchless XOR-fold; suitable for secret data comparisons.
     */
    inline bool ct_equal_raw(const void* a, const void* b, size_t n) {
        const auto* x = static_cast<const unsigned char*>(a);
        const auto* y = static_cast<const unsigned char*>(b);
        unsigned char v = 0;
        for (size_t i = 0; i < n; ++i) v |= (unsigned char)(x[i] ^ y[i]);
        return v == 0;
    }

    /**
     * @brief Constant-time equality for contiguous byte-like ranges of equal size.
     * @tparam A,B Contiguous ranges exposing 'data()' and 'size()'.
     * @return 'true' iff the byte contents are equal.
     */
    template<class A, class B>
    requires requires (const A& aa, const B& bb) {
        { std::ranges::data(aa) };
        { std::ranges::data(bb) };
        { std::ranges::size(aa) } -> std::convertible_to<std::size_t>;
        { std::ranges::size(bb) } -> std::convertible_to<std::size_t>;
            requires fenc::byte_like<
                std::remove_pointer_t<decltype(std::ranges::data(aa))>>;
                    requires fenc::byte_like<
                        std::remove_pointer_t<decltype(std::ranges::data(bb))>>;
    }
    [[nodiscard]] constexpr bool ct_equal_any(const A& aa, const B& bb) {
        if (std::ranges::size(aa) != std::ranges::size(bb)) return false;
        return ct_equal_raw(std::ranges::data(aa),
            std::ranges::data(bb),
            std::ranges::size(aa));
    }

    template<class A>
    inline bool ct_equal(const secure_string<A>& a, const secure_string<A>& b) {
        return ct_equal_any(a.s, b.s);
    }

    template<class CharT, class A>
    inline bool ct_equal(const basic_secure_string<CharT, A>& a, const basic_secure_string<CharT, A>& b) {
        return ct_equal_any(a.s, b.s);
    }

    /**
     * @brief RAII wrapper for 'OpenClipboard'/'CloseClipboard'.
     * Opens the clipboard on construction, empties it, and closes on destruction.
     */
    struct clipboard_guard {
        bool ok = false;
        clipboard_guard() { ok = !!OpenClipboard(nullptr); if (ok) EmptyClipboard(); }
        ~clipboard_guard() { if (ok) CloseClipboard(); }
        clipboard_guard(const clipboard_guard&) = delete;
        clipboard_guard& operator=(const clipboard_guard&) = delete;
    };

    /**
     * @brief RAII console mode guard.
     * Saves the current console mode and restores it on destruction.
     */
    struct scoped_console {
        HANDLE h;
        DWORD  oldMode{};
        bool   changed{ false };
        scoped_console(HANDLE handle, DWORD mode) : h(handle) {
            if (GetConsoleMode(h, &oldMode)) {
                DWORD inNew = mode;
                changed = !!SetConsoleMode(h, inNew);
            }
        }
        ~scoped_console() {
            if (changed) SetConsoleMode(h, oldMode);
        }
        scoped_console(const scoped_console&) = delete;
        scoped_console& operator=(const scoped_console&) = delete;
    };

    /**
     * @brief Unique owner for 'EVP_CIPHER_CTX'.
     * Allocates in the constructor and frees in the destructor.
     * @throws std::runtime_error on allocation failure.
     */
    struct EVP_CTX {
        EVP_CIPHER_CTX* p{ nullptr };
        EVP_CTX() : p(EVP_CIPHER_CTX_new()) { if (!p) throw std::runtime_error("EVP_CIPHER_CTX_new failed"); }
        ~EVP_CTX() { if (p) EVP_CIPHER_CTX_free(p); }
        EVP_CTX(const EVP_CTX&) = delete;
        EVP_CTX& operator=(const EVP_CTX&) = delete;
    };

    /**
     * @brief Enable heap termination on corruption for the current process.
     * @note Hardens against certain heap exploitation primitives.
     */
    static void harden_heap() {
        HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
    }

    /**
     * @brief Attempt to enable process-wide security mitigations via 'SetProcessMitigationPolicy'.
     *
     * Enables:
     *  - Prohibit dynamic code generation,
     *  - Prefer Microsoft-signed images,
     *  - Strict handle check policy,
     *  - Disable extension points,
     *  - Restrictive image load policy (no remote/low-IL images, prefer System32).
     *
     * @return TRUE on success for all applied policies, FALSE if the API is missing or a call fails.
     * @note Side-channel isolation policy block is present but currently has no specific flags set.
     */
    using PFN_SetProcessMitigationPolicy = BOOL(WINAPI*)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
    static BOOL set_secure_process_mitigations() {
        HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
        if (!hK32) return FALSE;

        auto pSet = (PFN_SetProcessMitigationPolicy)GetProcAddress(hK32, "SetProcessMitigationPolicy");
        if (!pSet) return FALSE;

        BOOL allSuccess = TRUE;

        // 1. Disable dynamic code generation (prevents JIT injection attacks)
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynCodePolicy = {};
        dynCodePolicy.ProhibitDynamicCode = 1;
        allSuccess &= pSet(ProcessDynamicCodePolicy, &dynCodePolicy, sizeof(dynCodePolicy));

        // 2. Require signed images only (prevents unsigned DLL injection)
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = {};
        sigPolicy.MicrosoftSignedOnly = 1;  // Or use MitigationOptIn for any signed code
        sigPolicy.AuditMicrosoftSignedOnly = 0;
        allSuccess &= pSet(ProcessSignaturePolicy, &sigPolicy, sizeof(sigPolicy));

        PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY sc{};
        sc.SmtBranchTargetIsolation = 1; // Spectre v2-ish isolation
        sc.IsolateSecurityDomain = 1; // Tighter domain isolation (if available)
        sc.DisablePageCombine = 1; // Opt out of page combining/dedup
        sc.SpeculativeStoreBypassDisable = 1; // SSB mitigation
        sc.RestrictCoreSharing = 1; // Avoid sibling SMT sharing

        allSuccess &= pSet(ProcessSideChannelIsolationPolicy, &sc, sizeof(sc));

        // 4. Enable strict handle checks
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = {};
        handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
        handlePolicy.HandleExceptionsPermanentlyEnabled = 1;
        allSuccess &= pSet(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy));

        // 5. Disable extension points (prevents third-party code injection)
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extPolicy = {};
        extPolicy.DisableExtensionPoints = 1;
        allSuccess &= pSet(ProcessExtensionPointDisablePolicy, &extPolicy, sizeof(extPolicy));

        // 6. Enable image load policy (restrict DLL loading locations)
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY imgPolicy = {};
        imgPolicy.NoRemoteImages = 1;            // Block loading from network shares
        imgPolicy.NoLowMandatoryLabelImages = 1; // Block low integrity images
        imgPolicy.PreferSystem32Images = 1;      // Prefer System32 versions
        allSuccess &= pSet(ProcessImageLoadPolicy, &imgPolicy, sizeof(imgPolicy));

        return allSuccess;
    }

    /**
     * @brief Try to enable 'SeLockMemoryPrivilege' for the current process token.
     * @return TRUE if the privilege is present and enabled ('GetLastError()==ERROR_SUCCESS'), else FALSE.
     * @note 'AdjustTokenPrivileges' can return TRUE even if the privilege wasn't assigned; we check 'GetLastError()'.
     */
    static BOOL try_enable_lock_privilege() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return FALSE;
        }

        TOKEN_PRIVILEGES tp{};
        LUID luid{};

        if (!LookupPrivilegeValueW(nullptr, SE_LOCK_MEMORY_NAME, &luid)) {
            CloseHandle(hToken);
            return FALSE;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // AdjustTokenPrivileges returns TRUE even if it fails to assign some privileges
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
            CloseHandle(hToken);
            return FALSE;
        }

        // CRITICAL: Check GetLastError() even when AdjustTokenPrivileges returns TRUE
        DWORD gle = GetLastError();
        CloseHandle(hToken);

        // ERROR_SUCCESS means all privileges were assigned
        // ERROR_NOT_ALL_ASSIGNED means the privilege doesn't exist in the token
        return (gle == ERROR_SUCCESS);
    }

    /**
     * @brief Securely wipe and release an STL string (narrow or wide).
     * Overwrites the current contents with 'OPENSSL_cleanse', then clears and shrinks.
     */
    template <class CharT, class Traits, class Alloc>
    inline void cleanse_one(std::basic_string<CharT, Traits, Alloc>& s) noexcept {
        if (!s.empty()) {
            OPENSSL_cleanse(static_cast<void*>(s.data()), s.size() * sizeof(CharT));
        }
        s.clear();
        s.shrink_to_fit();
    }

    template <class A>
    inline void cleanse_one(fenc::secure_string<A>& s) noexcept {
        if (!s.s.empty()) {
            char* base = s.s.data();
            if (base) {
                auto* hdr = fenc::header_from_payload(base);
                DWORD oldProt{}, dummy{};
                // Allow wiping even if the span was PAGE_NOACCESS'd elsewhere.
                (void)VirtualProtect(base, hdr->payloadSpan, PAGE_READWRITE, &oldProt);

                // Wipe ONLY the usable payload (capacity in bytes), never the tail canary.
                SecureZeroMemory(base, hdr->usable);

                // Restore previous protection.
                (void)VirtualProtect(base, hdr->payloadSpan, oldProt, &dummy);
            }
        }
        // Release without shrink_to_fit() to avoid mid-wipe reallocations.
        s.s.clear();
        std::vector<char, A>().swap(s.s);
    }

    template <class CharT, class A>
    inline void cleanse_one(fenc::basic_secure_string<CharT, A>& s) noexcept {
        if (!s.s.empty()) {
            CharT* base = s.s.data();
            if (base) {
                auto* hdr = fenc::header_from_payload(base);
                DWORD oldProt{}, dummy{};
                (void)VirtualProtect(base, hdr->payloadSpan, PAGE_READWRITE, &oldProt);
                SecureZeroMemory(base, hdr->usable);
                (void)VirtualProtect(base, hdr->payloadSpan, oldProt, &dummy);
            }
        }
        s.s.clear();
        std::vector<CharT, A>().swap(s.s);
    }

    template <fenc::byte_like T, class Alloc>
    inline void cleanse_one(std::vector<T, Alloc>& v) noexcept {
        if (!v.empty()) {
            OPENSSL_cleanse(static_cast<void*>(v.data()), v.size() * sizeof(T));
        }
        v.clear();
        v.shrink_to_fit();
    }

    template <class CharT>
    inline void cleanse_one(CharT* p, size_t len) noexcept {
        static_assert(std::is_trivial_v<CharT>, "CharT must be trivial");
        OPENSSL_cleanse(static_cast<void*>(p), len * sizeof(CharT));
    }

    // Null-terminated pointer (best-effort: uses current length)
    template <class CharT>
    inline void cleanse_one(CharT* p) noexcept {
        if (!p) return;
        const size_t n = std::char_traits<CharT>::length(p);
        cleanse_one(p, n);
    }

    inline void cleanse_string() noexcept {}
    template <class... Ts>
    inline void cleanse_string(Ts&&... xs) noexcept {
        (cleanse_one(std::forward<Ts>(xs)), ...);
    }

    /**
     * @brief Detect if the process is running in a Remote Desktop session.
     * @return true if 'SM_REMOTESESSION' is set.
     * @note Tool refuses to operate under remote sessions for safety.
     */
    static inline bool is_remote_session() { return GetSystemMetrics(SM_REMOTESESSION) != 0; }

    /**
     * @brief Case-insensitive check for whether a string ends with a given suffix (ASCII fold).
     *
     * This function performs a case-insensitive comparison of the end of the string to the provided suffix,
     * where the comparison ignores case differences in ASCII characters ('A' == 'a', etc.).
     *
     * @return 'true' if the string ends with the given suffix (case-insensitive), otherwise 'false'.
     */
    template<class CharT>
    [[nodiscard]] constexpr bool ends_with_ci(std::basic_string_view<CharT> s, std::basic_string_view<CharT> suf) {
        if (s.size() < suf.size()) return false;
        const size_t off = s.size() - suf.size();
        auto tolow = [](CharT c) constexpr -> CharT {
            if constexpr (sizeof(CharT) == 1) {
                if (c >= 'A' && c <= 'Z') c = static_cast<CharT>(c | 0x20);
            }
            else {
                if (c >= 'A' && c <= 'Z') c = static_cast<CharT>(c | 0x20);
            }
            return c;
            };
        for (size_t i = 0; i < suf.size(); ++i) {
            if (tolow(s[off + i]) != tolow(suf[i])) return false;
        }
        return true;
    }

    /**
     * @brief Trim leading and trailing whitespace from a string.
     *
     * This function removes any whitespace characters (spaces, tabs, etc.) from the beginning and the end of the string.
     *
     * @param s The string to trim.
     * @return A new string with leading and trailing whitespace removed.
     */
    [[nodiscard]] inline std::string trim(const std::string& s) {
        size_t a = 0, b = s.size();
        while (a < b && std::isspace((unsigned char)s[a])) ++a;
        while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
        return s.substr(a, b - a);
    }

    /**
     * @brief Remove surrounding quotes (single or double) from a string.
     *
     * This function removes a pair of quotes (either single or double) from the start and end of the string,
     * if they exist. If no quotes are found, the string is returned unchanged.
     *
     * @param s The string to process.
     * @return The string with surrounding quotes removed, if present.
     */
    [[nodiscard]] inline std::string stripQuotes(const std::string& s) {
        if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') ||
            (s.front() == '\'' && s.back() == '\'')))
            return s.substr(1, s.size() - 2);
        return s;
    }

    /**
     * @brief Get the basename of a file path (last part after the last backslash or forward slash).
     *
     * This function extracts the file name (basename) from a full path string, removing any directory paths.
     * It works with both forward and backward slashes as path separators.
     *
     * @param p The file path to process.
     * @return The basename of the file path.
     */
    [[nodiscard]] inline std::string basenameA(const std::string& p) {
        size_t i = p.find_last_of("\\/");
        return (i == std::string::npos) ? p : p.substr(i + 1);
    }

    /**
     * @brief Case-insensitive check for whether a string ends with a given suffix (ASCII fold).
     *
     * This is a convenience wrapper for 'ends_with_ci' with a 'std::string' argument and a C-style string suffix.
     *
     * @param s The string to check.
     * @param suf The suffix to check for.
     * @return 'true' if the string ends with the given suffix (case-insensitive), otherwise 'false'.
     */
    [[nodiscard]] inline bool endsWithCi(const std::string& s, const char* suf) {
        return ends_with_ci(std::string_view{ s }, std::string_view{ suf });
    }

    /**
     * @brief Encode a byte range as lowercase hex.
     * @tparam R Contiguous or input range of byte-like elements.
     * @return Hex string (no separators).
     */
    template<std::ranges::input_range R>
        requires byte_like<std::ranges::range_value_t<R>>
    [[nodiscard]] constexpr std::string to_hex(R&& range) {
        std::string out;
        constexpr auto hex_str = "0123456789abcdef";
        for (auto&& byte : range) {
            const auto b = static_cast<unsigned char>(byte);
            out.push_back(hex_str[b >> 4]);
            out.push_back(hex_str[b & 0x0F]);
        }
        return out;
    }

    /**
     * @brief Decode a hex string_view into an output iterator.
     * @param hex Even-length hex string (whitespace not allowed).
     * @param out Output iterator receiving decoded bytes.
     * @return false on invalid characters or odd length.
     */
    [[nodiscard]] constexpr bool from_hex_sv(std::string_view hex, std::output_iterator<unsigned char> auto out) {
        constexpr auto nib = [](unsigned char c) constexpr -> int {
            if (c >= '0' && c <= '9') return c - '0';
            c |= 0x20;
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            return -1;
            };
        if (hex.empty() || (hex.size() & 1)) return false;
        for (size_t i = 0; i < hex.size(); i += 2) {
            const auto hi = nib(static_cast<unsigned char>(hex[i]));
            const auto lo = nib(static_cast<unsigned char>(hex[i + 1]));
            if ((hi | lo) < 0) return false;
            *out++ = static_cast<unsigned char>((hi << 4) | lo);
        }
        return true;
    }

    /**
     * @brief Decode hex into a contiguous container, clearing and reserving appropriately.
     * @tparam Cont Contiguous container of byte-like elements with 'data()'/'reserve()'/'clear()'.
     * @return false on parse error.
     */
    template<std::ranges::contiguous_range Cont>
        requires byte_like<std::ranges::range_value_t<Cont>>
    [[nodiscard]] constexpr bool from_hex(std::string_view hex, Cont& out) {
        out.clear();
        out.reserve(hex.size() / 2);
        return from_hex_sv(hex, std::back_inserter(out));
    }

    [[nodiscard]] inline std::string stripSpaces(const std::string& s) {
        std::string r;
        r.reserve(s.size());
        for (unsigned char c : s) if (!std::isspace(c)) r.push_back((char)c);
        return r;
    }

    /**
     * @brief Extract candidate hex tokens (even length, all hex, length ≥ minimum packet size) from free text.
     * @return Vector of token strings suitable for decryption attempts.
     */
    [[nodiscard]] inline std::vector<std::string> extractHexTokens(const std::string& raw) {
        std::vector<std::string> tokens;
        std::string cur;
        for (unsigned char c : raw) {
            if (std::isspace(c)) {
                if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
            }
            else {
                cur.push_back((char)c);
            }
        }
        if (!cur.empty()) tokens.push_back(cur);

        constexpr size_t min_hex_chars = (cfg::SALT_LEN + cfg::IV_LEN + cfg::TAG_LEN) * 2;
        std::vector<std::string> good;
        for (auto& t : tokens) {
            if ((t.size() % 2) == 0 && t.size() >= min_hex_chars) {
                bool allhex = true;
                for (unsigned char c : t) if (!std::isxdigit(c)) { allhex = false; break; }
                if (allhex) good.push_back(t);
            }
        }
        return good;
    }

    /**
     * @brief Read an entire file into a contiguous container.
     * @tparam PathLike Convertible to 'std::filesystem::path'.
     * @tparam Cont Contiguous container of 'char' or byte-like elements.
     * @return true on success.
     */
    template<std::ranges::range PathLike, std::ranges::contiguous_range Cont>
        requires (byte_like<std::ranges::range_value_t<Cont>> ||
    std::same_as<std::ranges::range_value_t<Cont>, char>)
        [[nodiscard]] constexpr bool read_bin(const PathLike& p, Cont& out) {
        if constexpr (requires { std::filesystem::path{ p }; }) {
            std::ifstream in(std::filesystem::path{ p }, std::ios::binary);
            if (!in) return false;
            in.seekg(0, std::ios::end);
            const auto sz = in.tellg();
            if (sz < 0) return false;
            out.resize(static_cast<size_t>(sz));
            in.seekg(0, std::ios::beg);
            if (sz > 0) in.read(reinterpret_cast<char*>(out.data()), sz);
            return static_cast<bool>(in);
        }
        else {
            return false;
        }
    }

    /**
     * @brief Append a suffix/extension to a path string.
     * @param s   Base name or path.
     * @param ext Extension/suffix to append (e.g., ".pr$m"). Case is preserved.
     * @return New string equal to 's + ext'.
     * @note Pure string concatenation—does not validate 'ext', normalize separators,
     *       or touch the filesystem.
     */
    [[nodiscard]] inline std::string add_ext(const std::string& s, std::string_view ext) {
        return std::string(s) + std::string(ext);
    }

    /**
     * @brief Remove a trailing extension in a case-insensitive (ASCII-fold) manner.
     * @param s   Input name or path.
     * @param ext Extension to strip (e.g., ".pr$m"); compared case-insensitively.
     * @return 's' without the trailing 'ext' if it matches; otherwise returns 's' unchanged.
     * @warning ASCII case-fold only (no locale/Unicode awareness). Does not verify that 'ext'
     *          begins with a dot. Operates purely on the last 'ext.size()' characters.
     */
    [[nodiscard]] inline std::string strip_ext_ci(const std::string& s, std::string_view ext) {
        using CharT = char;
        if (s.size() >= ext.size() &&
            ends_with_ci(std::basic_string_view<CharT>(s.data(), s.size())
                .substr(s.size() - ext.size()),
                ext)) {
            return s.substr(0, s.size() - ext.size());
        }
        return s;
    }

    /**
     * @brief Check whether a path exists and refers to a non-directory file.
     * @param path Narrow (ACP) path.
     * @return true if attributes are valid and 'FILE_ATTRIBUTE_DIRECTORY' is not set.
     * @note Uses 'GetFileAttributesA'. Reparse points are not special-cased here.
     */
    [[nodiscard]] inline bool fileExistsA(const std::string& path) {
        DWORD a = GetFileAttributesA(path.c_str());
        return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
    }

    /**
     * @brief Test whether a path refers to a directory.
     * @param path Narrow (ACP) path.
     * @return true if attributes are valid and 'FILE_ATTRIBUTE_DIRECTORY' is set; false otherwise.
     */
    [[nodiscard]] inline bool isDirectoryA(const std::string& path) {
        DWORD a = GetFileAttributesA(path.c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
    }

    /**
     * @brief Join a directory and a leaf name with a single backslash if needed.
     * @param dir  Directory component; may already end with '\\' or '/'.
     * @param name Leaf filename (not modified).
     * @return Concatenated path. If 'dir' is empty, returns 'name' as-is.
     * @note No normalization or UNC handling. Leading separators in 'name' are not stripped.
     */
    [[nodiscard]] inline std::string joinPath(const std::string& dir, const char* name) {
        std::string r = dir;
        if (!r.empty() && r.back() != '\\' && r.back() != '/') r.push_back('\\');
        r.append(name);
        return r;
    }

    /**
     * @brief Set UTF-8 text on the Windows clipboard (converted to UTF-16).
     * @return true on success.
     */
    [[nodiscard]] inline bool setText(const std::string& text) {
        clipboard_guard cb;
        if (!cb.ok) return false;          // must have OpenClipboard + (ideally) EmptyClipboard()

        if (text.size() > static_cast<size_t>(INT_MAX)) return false;

        // Size query (no output buffer)
        int wlen = MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS,
            text.data(), static_cast<int>(text.size()),
            nullptr, 0);
        if (wlen <= 0) return false;

        SIZE_T bytes = (static_cast<SIZE_T>(wlen) + 1) * sizeof(wchar_t);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (!hMem) return false;

        wchar_t* p = static_cast<wchar_t*>(GlobalLock(hMem));
        if (!p) { GlobalFree(hMem); return false; }

        // Do the conversion
        int written = MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS,
            text.data(), static_cast<int>(text.size()),
            p, wlen);
        if (written <= 0) { GlobalUnlock(hMem); GlobalFree(hMem); return false; }

        p[written] = L'\0';
        GlobalUnlock(hMem);

        // On success, ownership transfers to the system; do NOT free hMem.
        if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
            GlobalFree(hMem);  // still ours on failure
            return false;
        }
        return true;
    }

    /**
     * @brief Copy data to the clipboard with a time-to-live scrub.
     * After 'ttl_ms', clears the clipboard if unchanged and scrubs the source buffer.
     * @param data Pointer to bytes.
     * @param n Byte count.
     * @param ttl_ms Milliseconds to keep on the clipboard.
     * @return true on success.
     * @warning Clipboard contents are globally visible to the session; TTL only reduces exposure window.
     */
    [[nodiscard]] inline bool copyWithTTLGeneric(const char* data, size_t n, DWORD ttl_ms = 6000) {
        std::string val(data, n);
        bool ok = setText(val);
        if (!ok) return false;

        std::thread([val = std::move(val), ttl_ms]() mutable {
            Sleep(ttl_ms);
            clipboard_guard cb;
            if (cb.ok) {
                HANDLE h = GetClipboardData(CF_UNICODETEXT);
                bool same = false;
                if (h) {
                    if (wchar_t* w = (wchar_t*)GlobalLock(h)) {
                        int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
                        std::string cur(need ? (size_t)need - 1 : 0, '\0');
                        if (need) WideCharToMultiByte(CP_UTF8, 0, w, -1, cur.data(), need, nullptr, nullptr);
                        GlobalUnlock(h);
                        same = fenc::ct_equal_any(cur, val);
                    }
                }
                if (same) EmptyClipboard();
            }
            fenc::cleanse_string(val.data());
            }).detach();

        return true;
    }

    template<std::ranges::contiguous_range S>
        requires std::same_as<std::remove_cv_t<std::ranges::range_value_t<S>>, char>
    [[nodiscard]] inline bool copyWithTTL_any(const S& s, DWORD ttl_ms = 6000) {
        return copyWithTTLGeneric(std::ranges::data(s), std::ranges::size(s), ttl_ms);
    }

    template <size_t N>
    [[nodiscard]] inline bool copyWithTTL_any(const char(&s)[N], DWORD ttl_ms = 6000) {
        static_assert(N > 0, "empty char array?");
        return copyWithTTLGeneric(s, N - 1, ttl_ms);
    }

    [[nodiscard]] inline bool copyWithTTL_any(const char* s, DWORD ttl_ms = 6000) {
        return copyWithTTLGeneric(s ? s : "", s ? std::strlen(s) : 0, ttl_ms);
    }

    /**
     * @brief Type a UTF-16 string into the active window using 'SendInput' (Unicode scans).
     * @param bytes UTF-16 buffer (not necessarily null-terminated).
     * @param len Length in code units, or <0 to treat as null-terminated.
     * @param delay_ms Delay before typing (to allow the user to focus the target field).
     * @return true on success.
     * @warning Sends keystrokes to the foreground window; ensure focus is correct.
     */
    [[nodiscard]] inline bool typeSecretUTF8(const wchar_t* bytes, int len, DWORD delay_ms = 4000) {
        if (!bytes) return false;

        std::wstring w;
        if (len < 0) {
            // Treat as null-terminated wide string
            w = std::wstring(bytes);
            if (w.empty()) return false;
        }
        else {
            if (len <= 0) return false;
            w.assign(bytes, bytes + static_cast<size_t>(len));
            // If caller included the terminator in len, drop it
            if (!w.empty() && w.back() == L'\0') w.pop_back();
        }

        Sleep(delay_ms);

        std::vector<INPUT> seq;
        seq.reserve((size_t)w.size() * 2);
        for (wchar_t ch : w) {
            INPUT down{};
            down.type = INPUT_KEYBOARD;
            down.ki.wScan = ch;
            down.ki.dwFlags = KEYEVENTF_UNICODE;
            INPUT up = down;
            up.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            seq.push_back(down);
            seq.push_back(up);
        }
        for (size_t i = 0; i < seq.size(); ++i) {
            SendInput(1, &seq[i], sizeof(INPUT));
            if ((i & 1) == 1) Sleep(5 + (GetTickCount64() & 7));
        }

        SecureZeroMemory(seq.data(), seq.size() * sizeof(INPUT));
        SecureZeroMemory(w.data(), w.size() * sizeof(wchar_t));
        return true;
    }

    [[nodiscard]] inline bool openInputTxtInNotepad() {
        const char* file = "fence";
        HINSTANCE h = ShellExecuteA(nullptr, "open", "notepad.exe", file, nullptr, SW_SHOWNORMAL);
        if ((INT_PTR)h <= 32) {
            int ret = system("cmd /c start \"\" notepad.exe fence");
            return (ret == 0);
        }
        return true;
    }

    [[nodiscard]] inline bool copyInputTxtToClipboard() {
        std::string buf;
        if (!read_bin("fence", buf)) return false;
        return copyWithTTL_any(buf);
    }

    inline void wipeConsoleBuffer() {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) return;

        CONSOLE_SCREEN_BUFFER_INFO info{};
        if (!GetConsoleScreenBufferInfo(hOut, &info)) return;

        DWORD cells = (DWORD)info.dwSize.X * (DWORD)info.dwSize.Y;
        COORD home{ 0, 0 };
        DWORD written = 0;

        FillConsoleOutputCharacterA(hOut, ' ', cells, home, &written);
        FillConsoleOutputAttribute(hOut, info.wAttributes, cells, home, &written);
        SetConsoleCursorPosition(hOut, home);
    }

    /**
     * @brief Check an OpenSSL return code and throw with a decoded error string on failure.
     * @param ok OpenSSL boolean success (1 == success).
     * @param msg Context message.
     */
    inline void opensslCheck(int ok, const char* msg) {
        if (ok != 1) {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            std::ostringstream oss;
            oss << msg << " (OpenSSL: " << buf << ")";
            throw std::runtime_error(oss.str());
        }
    }

    /**
     * @brief Derive an AES-256 key from a secure string using scrypt.
     * @tparam SecurePwd Secure password type exposing '.s.data()' and '.s.size()'.
     * @param pwd Password container (wide/narrow supported).
     * @param salt 16-byte salt.
     * @return 32-byte key.
     * @note Parameters: N=32768, r=8, p=1, maxmem=128 MiB. Uses RW guard to access locked memory.
     */
    template<class SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> deriveKey(
        const SecurePwd& pwd,
        std::span<const unsigned char> salt
    ) {
        using CharT = std::remove_pointer_t<decltype(pwd.s.data())>;
        std::vector<unsigned char> key(fenc::cfg::KEY_LEN);

        fenc::RWGuard<CharT> guard(pwd.s.data());

        // scrypt parameters
        constexpr uint64_t N = 1ULL << 16;  // Increase N for higher security
        constexpr uint64_t r = 8;
        constexpr uint64_t p = 1;
        constexpr uint64_t maxmem = 128ULL * 1024 * 1024;

        const char* pass = nullptr;
        size_t passlen = 0;

        if (pwd.s.size() != 0) {
            pass = reinterpret_cast<const char*>(pwd.s.data());
            passlen = pwd.s.size() * sizeof(CharT);
        }

        opensslCheck(
            EVP_PBE_scrypt(pass, passlen,
                salt.data(), salt.size(),
                N, r, p, maxmem,
                key.data(), key.size()),
            "scrypt failed"
        );

        return key;
    }

    /**
     * @brief Get the authenticated AAD span for packet framing.
     * @return 4-byte read-only span.
     */
    inline std::span<const unsigned char> aad_span() noexcept {
        return {
            reinterpret_cast<const unsigned char*>(fenc::cfg::AAD_HDR),
            static_cast<std::size_t>(fenc::cfg::AAD_LEN)
        };
    }

    /**
     * @brief Encrypt plaintext bytes into a framed packet.
     * @tparam SecurePwd Secure password type as in @ref deriveKey.
     * @param plaintext Bytes to encrypt.
     * @param password Password container.
     * @return Packet = '[AAD | salt | iv | ciphertext | tag]'.
     * @throws std::runtime_error on any OpenSSL failure.
     * @post Derived key material is scrubbed.
     */
    template<class SecurePwd>
    [[nodiscard]] inline std::vector<unsigned char>
        encrypt_packet(std::span<const unsigned char> plaintext,
            const SecurePwd& password)
    {
        std::span<const unsigned char> aad = aad_span();

        // salt and key
        std::vector<unsigned char> salt(fenc::cfg::SALT_LEN);
        opensslCheck(RAND_bytes(salt.data(), (int)salt.size()), "RAND_bytes(salt) failed");
        auto key = fenc::deriveKey(password, std::span<const unsigned char>(salt));

        // iv
        std::vector<unsigned char> iv(fenc::cfg::IV_LEN);
        opensslCheck(RAND_bytes(iv.data(), (int)iv.size()), "RAND_bytes(iv) failed");

        fenc::EVP_CTX ctx;
        opensslCheck(EVP_EncryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
            "EncryptInit(cipher) failed");
        opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr),
            "SET_IVLEN failed");
        opensslCheck(EVP_EncryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv.data()),
            "EncryptInit(key/iv) failed");

        // AAD (optional)
        if (!aad.empty()) {
            int tmp = 0;
            opensslCheck(EVP_EncryptUpdate(ctx.p, nullptr, &tmp, aad.data(), (int)aad.size()),
                "EncryptUpdate(AAD) failed");
        }

        // Encrypt
        std::vector<unsigned char> ct(plaintext.size() + 16 /*block slop*/);
        int outlen = 0, fin = 0;
        opensslCheck(EVP_EncryptUpdate(ctx.p, ct.data(), &outlen,
            plaintext.data(), (int)plaintext.size()),
            "EncryptUpdate(PT) failed");
        int total = outlen;
        opensslCheck(EVP_EncryptFinal_ex(ctx.p, ct.data() + total, &fin),
            "EncryptFinal failed");
        total += fin;
        ct.resize((size_t)total);

        // Tag
        std::vector<unsigned char> tag(fenc::cfg::TAG_LEN);
        opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()),
            "GET_TAG failed");

        // Serialize packet
        std::vector<unsigned char> out;
        out.reserve(aad.size() + salt.size() + iv.size() + ct.size() + tag.size());
        if (!aad.empty()) out.insert(out.end(), aad.begin(), aad.end());
        out.insert(out.end(), salt.begin(), salt.end());
        out.insert(out.end(), iv.begin(), iv.end());
        out.insert(out.end(), ct.begin(), ct.end());
        out.insert(out.end(), tag.begin(), tag.end());

        fenc::cleanse_string(key);
        return out;
    }

    /**
     * @brief Decrypt a framed packet back to plaintext.
     * @tparam SecurePwd Secure password type as in @ref deriveKey.
     * @param packet Framed bytes as produced by @ref encrypt_packet.
     * @param password Password container.
     * @return Plaintext bytes.
     * @throws std::runtime_error on AAD mismatch, length errors, or auth failure.
     * @post Derived key material is scrubbed.
     */
    template<class SecurePwd>
    [[nodiscard]] inline std::vector<unsigned char>
        decrypt_packet(std::span<const unsigned char> packet,
            const SecurePwd& password)
    {
        std::span<const unsigned char> aad_expected = aad_span();
        const unsigned char* p = packet.data();
        size_t n = packet.size();

        // If AAD required, verify & strip it
        size_t off = 0;
        if (!aad_expected.empty()) {
            if (n < aad_expected.size())
                throw std::runtime_error("Ciphertext too short (missing AAD)");
            if (std::memcmp(p, aad_expected.data(), aad_expected.size()) != 0)
                throw std::runtime_error("Bad AAD header");
            off = aad_expected.size();
        }

        // Structure sizes
        if (n < off + fenc::cfg::SALT_LEN + fenc::cfg::IV_LEN + fenc::cfg::TAG_LEN)
            throw std::runtime_error("Ciphertext too short");

        const unsigned char* salt = p + off;
        const unsigned char* iv = p + off + fenc::cfg::SALT_LEN;
        const unsigned char* ct = p + off + fenc::cfg::SALT_LEN + fenc::cfg::IV_LEN;

        size_t ct_len_with_tag = n - off - fenc::cfg::SALT_LEN - fenc::cfg::IV_LEN;
        if (ct_len_with_tag < fenc::cfg::TAG_LEN)
            throw std::runtime_error("Invalid ciphertext/tag sizes");

        size_t ct_len = ct_len_with_tag - fenc::cfg::TAG_LEN;
        const unsigned char* tag = ct + ct_len;

        // Derive key
        auto key = fenc::deriveKey(password,
            std::span<const unsigned char>(salt, fenc::cfg::SALT_LEN));

        fenc::EVP_CTX ctx;
        opensslCheck(EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
            "DecryptInit(cipher) failed");
        opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)fenc::cfg::IV_LEN, nullptr),
            "SET_IVLEN failed");
        opensslCheck(EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv),
            "DecryptInit(key/iv) failed");

        // AAD (if required)
        if (!aad_expected.empty()) {
            int tmp = 0;
            opensslCheck(EVP_DecryptUpdate(ctx.p, nullptr, &tmp,
                aad_expected.data(), (int)aad_expected.size()),
                "DecryptUpdate(AAD) failed");
        }

        // Decrypt
        std::vector<unsigned char> plain(ct_len);
        int outlen = 0, fin = 0;
        opensslCheck(EVP_DecryptUpdate(ctx.p, plain.data(), &outlen, ct, (int)ct_len),
            "DecryptUpdate(CT) failed");

        // Set tag and finalize (auth check happens here)
        opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, (int)fenc::cfg::TAG_LEN,
            const_cast<unsigned char*>(tag)),
            "SET_TAG failed");

        int ok = EVP_DecryptFinal_ex(ctx.p, plain.data() + outlen, &fin);
        if (ok != 1) {
            fenc::cleanse_string(key);
            throw std::runtime_error("Authentication failed (bad password or corrupted data)");
        }

        plain.resize((size_t)(outlen + fin));
        fenc::cleanse_string(key);
        return plain;
    }

    /**
     * @brief RAII holder for three narrow secure strings (service, user, pass).
     * Move-only; members are wiped on destruction via their allocators.
     */
    template<class A = fenc::locked_allocator<char>>
    struct secure_triplet {
        fenc::secure_string<A> service, user, pass;

        secure_triplet(fenc::secure_string<A>&& s, fenc::secure_string<A>&& u, fenc::secure_string<A>&& p) noexcept
            : service(std::move(s)), user(std::move(u)), pass(std::move(p)) {
        }

        secure_triplet(secure_triplet&&) noexcept = default;
        secure_triplet& operator=(secure_triplet&&) noexcept = default;
        secure_triplet(const secure_triplet&) = delete;
        secure_triplet& operator=(const secure_triplet&) = delete;
    };
    using secure_triplet_t = secure_triplet<>;

    /**
     * @brief RAII holder for three wide secure strings (primary/secondary/tertiary).
     * Provides tuple-like accessors and bounds-checked 'at()'.
     * @note Intended to hold (service, username, password) in UTF-16.
     */
    template<class A = fenc::locked_allocator<wchar_t>>
    struct secure_triplet16 {
        using string_type = fenc::basic_secure_string<wchar_t, A>;

        // Keep original names
        string_type primary, secondary, tertiary;

        secure_triplet16(string_type&& s, string_type&& u, string_type&& p) noexcept
            : primary(std::move(s)), secondary(std::move(u)), tertiary(std::move(p)) {
        }

        secure_triplet16(secure_triplet16&&) noexcept = default;
        secure_triplet16& operator=(secure_triplet16&&) noexcept = default;
        secure_triplet16(const secure_triplet16&) = delete;
        secure_triplet16& operator=(const secure_triplet16&) = delete;

        // Element count
        static constexpr std::size_t size() noexcept { return 3; }

        // [] Access (unchecked, like std::array::operator[])
        string_type& operator[](std::size_t i) noexcept {
            assert(i < 3);
            switch (i) {
            case 0: return primary;
            case 1: return secondary;
            default: return tertiary;
            }
        }
        const string_type& operator[](std::size_t i) const noexcept {
            assert(i < 3);
            switch (i) {
            case 0: return primary;
            case 1: return secondary;
            default: return tertiary;
            }
        }

        // Bounds-checked access
        string_type& at(std::size_t i) {
            if (i >= 3) throw std::out_of_range("secure_triplet::at");
            return (*this)[i];
        }
        const string_type& at(std::size_t i) const {
            if (i >= 3) throw std::out_of_range("secure_triplet::at");
            return (*this)[i];
        }

        // First/second/third accessors
        string_type& first() noexcept { return primary; }
        string_type& second() noexcept { return secondary; }
        string_type& third() noexcept { return tertiary; }

        const string_type& first()  const noexcept { return primary; }
        const string_type& second() const noexcept { return secondary; }
        const string_type& third()  const noexcept { return tertiary; }

        // Tuple-like member get<I>()
        template<std::size_t I>
        decltype(auto) get() & noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
        template<std::size_t I>
        decltype(auto) get() const& noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
        template<std::size_t I>
        decltype(auto) get() && noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
        template<std::size_t I>
        decltype(auto) get() const&& noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
    };
    using secure_triplet16_t = secure_triplet16<>;

} // namespace fenc

// ============================================================================
// Wrapper functions for backward compatibility
// ============================================================================

template<class SecurePwd>
static bool encryptFileOverwriteSelf(const char* path, const SecurePwd & pwd) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { std::cerr << "(encrypt) cannot open: " << path << "\n"; return false; }
    std::vector<unsigned char> plain((std::istreambuf_iterator<char>(in)), {});
    auto packet = fenc::encrypt_packet(std::span<const unsigned char>(plain), pwd);
    fenc::cleanse_string(plain);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { std::cerr << "(encrypt) cannot overwrite: " << path << "\n"; return false; }
    out.write(reinterpret_cast<const char*>(packet.data()), (std::streamsize)packet.size());
    return (bool)out;
}

template<class SecurePwd>
static bool decryptFileOverwriteSelf(const char* path, const SecurePwd & pwd) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { std::cerr << "(decrypt) cannot open: " << path << "\n"; return false; }
    std::vector<unsigned char> blob((std::istreambuf_iterator<char>(in)), {});
    try {
        auto plain = fenc::decrypt_packet(std::span<const unsigned char>(blob), pwd);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) { std::cerr << "(decrypt) cannot overwrite: " << path << "\n"; return false; }
        out.write(reinterpret_cast<const char*>(plain.data()), (std::streamsize)plain.size());
        fenc::cleanse_string(plain);
        return (bool)out;
    }
    catch (const std::exception& e) {
        std::cerr << "(decrypt) " << e.what() << "\n";
        return false;
    }
}

template<class SecurePwd>
[[nodiscard]] std::string encryptLine(const std::string & s, const SecurePwd & pwd) {
    auto packet = fenc::encrypt_packet(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size()), pwd);
    return fenc::to_hex(packet);
}

template<class SecurePwd>
[[nodiscard]] fenc::secure_string<fenc::locked_allocator<char>>
decryptLine(const std::string & rawHex, const SecurePwd & pwd) {
    std::string compact = fenc::stripSpaces(rawHex);
    std::vector<unsigned char> blob;
    if (!fenc::from_hex(std::string_view{ compact }, blob)) throw std::runtime_error("Invalid hex input");
    auto bytes = fenc::decrypt_packet(std::span<const unsigned char>(blob), pwd);
    fenc::secure_string<fenc::locked_allocator<char>> out;
    out.s.assign(reinterpret_cast<const char*>(bytes.data()),
        reinterpret_cast<const char*>(bytes.data()) + bytes.size());
    fenc::cleanse_string(bytes);
    return out;
}

// ============================================================================
// Triple helpers
// ============================================================================

/**
 * @brief Compute serialized length of a UTF-16 triple when rendered as 's:u:p' (in UTF-8).
 */
template<class A>
static inline size_t tripleLen(const fenc::secure_triplet16<A>&t) {
    return t.primary.size() + 1 + t.secondary.size() + 1 + t.tertiary.size();
}

/**
 * @brief Convert a UTF-16 triple to a single UTF-8 line 'service:username:password'.
 * @warning Produces a transient narrow string containing secrets; wipe after use.
 */
static inline std::string tripleToUtf8(const fenc::secure_triplet16_t & t) {
    auto to_utf8 = [](auto& w) {
        if (w.size() == 0) return std::string{};
        int need = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string out(need, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), out.data(), need, nullptr, nullptr);
        return out;
        };
    std::string s = to_utf8(t.primary), u = to_utf8(t.secondary), p = to_utf8(t.tertiary);
    std::string out; out.reserve(s.size() + u.size() + p.size() + 2);
    out.append(s).push_back(':'); out.append(u).push_back(':'); out.append(p);
    return out;
}

/**
 * @brief Parse one or more 'service:username:password' items from a plain text view.
 * Splits on ',' or newline boundaries; trims per-item whitespace; enforces exactly two colons per item.
 * @tparam A Locked allocator for 'wchar_t'.
 * @param plain Narrow plain text input (UTF-8 expected).
 * @param out Destination vector of secure UTF-16 triplets (moved in).
 * @return true on success (non-empty result with only well-formed items).
 */
template<class A>
static bool parseTriples(std::string_view plain, std::vector<fenc::secure_triplet16<A>>&out) {
    out.clear();
    std::string tok;

    auto flush = [&](std::string& t) -> bool {
        std::string s = fenc::trim(t);
        t.clear();
        if (s.empty()) return true;

        size_t c1 = s.find(':'), c2 = (c1 == std::string::npos ? std::string::npos : s.find(':', c1 + 1));
        if (c1 == std::string::npos || c2 == std::string::npos || s.find(':', c2 + 1) != std::string::npos)
            return false;

        auto mk = [&](size_t off, size_t len) {
            fenc::basic_secure_string<wchar_t, A> r;
            r.s.assign(s.begin() + off, s.begin() + off + len);
            return r;
            };

        out.emplace_back(
            mk(0, c1),
            mk(c1 + 1, c2 - (c1 + 1)),
            mk(c2 + 1, s.size() - (c2 + 1))
        );
        return true;
        };

    for (char ch : plain) {
        if (ch == ',' || ch == '\n' || ch == '\r') {
            if (!flush(tok)) { out.clear(); return false; }
        }
        else {
            tok.push_back(ch);
        }
    }
    if (!flush(tok)) { out.clear(); return false; }
    return !out.empty();
}

/**
 * @brief Interactive masked console UI to type usernames/passwords into the active window.
 *
 * Renders a bottom-anchored list like 'N) service: ********:********'. Clicking on the
 * user or password region starts a short countdown, then injects keystrokes (UTF-16)
 * into the foreground window. Enter/Esc exits.
 *
 * @warning Does not touch the clipboard. Ensure focus is on the intended input control.
 */
struct Regions { SHORT y, u0, u1, p0, p1; };
static void interactiveMaskedWin(const std::vector<fenc::secure_triplet16_t>&T) {
    constexpr int COUNTDOWN_SEC = 3;

    HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD inOld = 0; GetConsoleMode(hin, &inOld);
    DWORD inNew = (inOld | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE;
    fenc::scoped_console modeGuard(hin, inNew);
    FlushConsoleInputBuffer(hin);

    CONSOLE_SCREEN_BUFFER_INFO info{};
    GetConsoleScreenBufferInfo(hout, &info);
    const SHORT width = info.dwSize.X;
    const SHORT winTop = info.srWindow.Top;
    const SHORT winBot = info.srWindow.Bottom;
    const SHORT winH = (SHORT)(winBot - winTop + 1);

    int maxItems = std::max<SHORT>(0, (SHORT)(winH - 2));
    int showCount = (int)std::min<size_t>((size_t)maxItems, T.size());
    int needed = 1 + showCount + 1;

    SHORT startY = (SHORT)(winBot - needed + 1);
    if (startY < winTop) startY = winTop;

    std::string blank((size_t)width, ' ');
    for (SHORT r = startY; r < startY + needed && r <= winBot; ++r) {
        COORD c{ 0, r }; DWORD w = 0;
        SetConsoleCursorPosition(hout, c);
        WriteConsoleA(hout, blank.c_str(), (DWORD)blank.size(), &w, nullptr);
    }

    SetConsoleCursorPosition(hout, { 0, startY });
    DWORD w;
    WriteConsoleA(hout,
        "--- Decrypted entries (Click **** to copy; Enter/Esc to continue) ---",
        69, &w, nullptr);
    SetConsoleCursorPosition(hout, { 0, (SHORT)(startY + 1) });

    std::vector<Regions> R; R.reserve((size_t)showCount);

    for (int i = 0; i < showCount; ++i) {
        GetConsoleScreenBufferInfo(hout, &info);
        SHORT y = info.dwCursorPosition.Y;

        std::wstring idx = std::to_wstring(i + 1) + L") ";
        constexpr int MASKED_TAIL = 1 + 8 + 1 + 8; // 18

        int max_service = std::max<SHORT>(0, (SHORT)(width - (int)idx.size() - MASKED_TAIL));

        std::wstring svc(T[(size_t)i].primary.data(), T[(size_t)i].primary.size());

        if ((int)svc.size() > max_service) {
            if (max_service >= 1) {
                int keep = std::max(0, max_service - 3);
                svc = svc.substr(0, keep) + (keep > 0 ? L"..." : L"");
            }
            else {
                svc.clear();
            }
        }

        std::wstring prefix = idx + svc + L":";
        std::wstring line = prefix + L"********:********";

        SetConsoleCursorPosition(hout, { 0, y });
        WriteConsoleW(hout, line.c_str(), (DWORD)line.size(), &w, nullptr);
        SetConsoleCursorPosition(hout, { 0, (SHORT)(y + 1) });

        SHORT u0 = (SHORT)prefix.size();
        SHORT u1 = (SHORT)(u0 + 8 - 1);
        SHORT p0 = (SHORT)(u1 + 2);
        SHORT p1 = (SHORT)(p0 + 8 - 1);
        R.push_back(Regions{ y, u0, u1, p0, p1 });
    }

    GetConsoleScreenBufferInfo(hout, &info);
    SHORT statusY = info.dwCursorPosition.Y;
    auto status = [&](const std::string& msg) {
        GetConsoleScreenBufferInfo(hout, &info);
        std::string blank2((size_t)info.dwSize.X, ' ');
        COORD c{ 0, statusY }; DWORD ww;
        SetConsoleCursorPosition(hout, c);
        WriteConsoleA(hout, blank2.c_str(), (DWORD)blank2.size(), &ww, nullptr);
        SetConsoleCursorPosition(hout, c);
        WriteConsoleA(hout, msg.c_str(), (DWORD)msg.size(), &ww, nullptr);
        };

    auto statusw = [&](const std::wstring& msg) {
        GetConsoleScreenBufferInfo(hout, &info);
        std::string blank2((size_t)info.dwSize.X, ' ');
        COORD c{ 0, statusY }; DWORD ww;
        SetConsoleCursorPosition(hout, c);
        WriteConsoleA(hout, blank2.c_str(), (DWORD)blank2.size(), &ww, nullptr);
        SetConsoleCursorPosition(hout, c);
        WriteConsoleW(hout, msg.c_str(), (DWORD)msg.size(), &ww, nullptr);
        };

    if ((size_t)showCount < T.size()) {
        status("[showing " + std::to_string(showCount) + " of " + std::to_string(T.size()) + "]");
    }
    else {
        status("");
    }

    INPUT_RECORD rec{}; DWORD nread = 0;
    while (ReadConsoleInput(hin, &rec, 1, &nread)) {
        if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
            WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;
            if (vk == VK_RETURN || vk == VK_ESCAPE) break;
        }
        if (rec.EventType == MOUSE_EVENT) {
            const auto& m = rec.Event.MouseEvent;
            if (m.dwEventFlags == 0 && (m.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED)) {
                SHORT x = m.dwMousePosition.X, y = m.dwMousePosition.Y;
                for (size_t i = 0; i < R.size(); ++i) if (y == R[i].y) {
                    const auto& e = T[i];
                    std::wstring svc(e.primary.data(), e.primary.size());
                    if (x >= R[i].u0 && x <= R[i].u1) {
                        for (int s = COUNTDOWN_SEC; s >= 1; --s) {
                            status("Focus target field; typing USERNAME in " + std::to_string(s) + "s");
                            Sleep(1000);
                        }
                        (void)fenc::typeSecretUTF8(e.secondary.data(), (int)e.secondary.size(), 0);
                        statusw(L"[typed] " + svc + L" username");
                    }
                    else if (x >= R[i].p0 && x <= R[i].p1) {
                        for (int s = COUNTDOWN_SEC; s >= 1; --s) {
                            status("Focus target field; typing PASSWORD in " + std::to_string(s) + "s");
                            Sleep(1000);
                        }
                        (void)fenc::typeSecretUTF8(e.tertiary.data(), (int)e.tertiary.size(), 0);
                        statusw(L"[typed] " + svc + L" password");
                    }
                    break;
                }
            }
        }
    }

    SetConsoleCursorPosition(hout, { 0, (SHORT)(statusY + 1) });
}

/**
 * @brief Read multiple non-empty lines from stdin until '?' (masked) or '!' (uncensored).
 * Recognizes ':open', ':copy', and ':none' commands for convenience.
 * @return Pair of {lines, uncensored_flag}.
 */
static std::pair<std::vector<std::string>, bool> readBulkLinesDualFrom(std::istream & in) {
    std::vector<std::string> lines;
    std::string l;
    bool uncensored = false;
    while (true) {
        if (!std::getline(in, l)) break;
        std::string t = fenc::trim(l);
        if (t == "?" || t == "!") { uncensored = (t == "!"); break; }
        if (!t.empty()) lines.push_back(l);
    }
    return { std::move(lines), uncensored };
}

static bool readBulkLinesDualOrEsc(std::pair<std::vector<std::string>, bool>&out) {
    std::vector<std::string> lines;
    std::string cur;
    bool uncensored = false;

    for (;;) {
        int ch = _getch();

        if (ch == 27) return false;              // Esc -> exit
        if (ch == 3)  throw std::runtime_error("Interrupted");
        if (ch == 26) throw std::runtime_error("EOF");

        if (ch == '\r' || ch == '\n') {
            std::string t = fenc::trim(cur);

            if (t == "?" || t == "!") {
                uncensored = (t == "!");
                std::cout << "\n";
                break;
            }

            if (t == ":open" || t == ":o" || t == ":edit") {
                if (!fenc::openInputTxtInNotepad()) std::cerr << "(failed to launch Notepad)\n";
                cur.clear();
                std::cout << "\n";
                continue;
            }

            if (t == ":copy" || t == ":clip" || t == ":copyfile" || t == ":copyinput") {
                bool ok = fenc::copyInputTxtToClipboard();
                std::cout << (ok ? "(fence copied to clipboard)" : "(failed to copy fence)") << "\n";
                cur.clear();
                continue;
            }

            if (t == ":none" || t == ":clear") {
                (void)fenc::copyWithTTL_any("");
                std::cout << "(clipboard cleaned)\n";
                cur.clear();
                continue;
            }

            if (!t.empty()) lines.push_back(cur);
            cur.clear();
            std::cout << "\n";
            continue;
        }

        if (ch == 8) {
            if (!cur.empty()) {
                cur.pop_back();
                std::cout << "\b \b" << std::flush;
            }
            continue;
        }

        if (ch == 0 || ch == 224) { (void)_getch(); continue; }

        cur.push_back((char)ch);
        std::cout << (char)ch << std::flush;
    }

    out = { std::move(lines), uncensored };
    return true;
}

/**
 * @brief Prompt for a password using Windows Credentials UI.
 * @param caption Dialog caption.
 * @param message Dialog message text.
 * @return Secure UTF-16 password string.
 * @throws std::runtime_error on cancel or API failure.
 * @note Uses 'CredUIPromptForWindowsCredentialsW'; no secure-desktop flag is requested here.
 *       Extracted buffers are immediately scrubbed.
 */
static fenc::basic_secure_string<wchar_t> readPasswordSecureDesktop(
    const wchar_t* caption = L"FenceLock AES-256-GCM",
    const wchar_t* message = L"Enter your master password."
) {
    CREDUI_INFOW ui{};
    ui.cbSize = sizeof(ui);
    ui.hwndParent = nullptr;
    ui.pszCaptionText = caption;
    ui.pszMessageText = message;

    DWORD inLen = 0;
    wchar_t user_prefill[] = L"";
    wchar_t pass_empty[] = L"";

    (void)CredPackAuthenticationBufferW(0, user_prefill, pass_empty, nullptr, &inLen);

    std::vector<BYTE> inBuf(inLen);
    if (!CredPackAuthenticationBufferW(0, user_prefill, pass_empty, inBuf.data(), &inLen)) {
        throw std::runtime_error("CredPackAuthenticationBufferW failed");
    }

    DWORD authPkg = 0;
    LPVOID outBuf = nullptr;
    ULONG  outLen = 0;

    const DWORD flags = CREDUIWIN_ENUMERATE_CURRENT_USER;

    HRESULT hr = CredUIPromptForWindowsCredentialsW(
        &ui, 0, &authPkg,
        inBuf.data(), inLen,
        &outBuf, &outLen,
        nullptr, flags);

    if (hr != ERROR_SUCCESS) throw std::runtime_error("User canceled");

    wchar_t user[256]{}, dom[256]{}, pass[512]{};
    DWORD u = _countof(user), d = _countof(dom), p = _countof(pass);

    BOOL ok = CredUnPackAuthenticationBufferW(
        CRED_PACK_PROTECTED_CREDENTIALS,
        outBuf, outLen, user, &u, dom, &d, pass, &p);

    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_CAPABLE || err == ERROR_NOT_SUPPORTED) {
            u = _countof(user); d = _countof(dom); p = _countof(pass);
            ok = CredUnPackAuthenticationBufferW(0, outBuf, outLen, user, &u, dom, &d, pass, &p);
        }
    }

    if (outBuf && outLen) SecureZeroMemory(outBuf, outLen);
    if (outBuf) CoTaskMemFree(outBuf);
    if (!ok) throw std::runtime_error("CredUnPackAuthenticationBufferW failed");

    // Store password as UTF-16 (char16_t)
    size_t need16 = wcslen(pass);
    fenc::basic_secure_string<wchar_t> out;
    out.s.resize(need16);
    for (size_t i = 0; i < need16; ++i) out.s[i] = static_cast<char16_t>(pass[i]);

    SecureZeroMemory(pass, sizeof(pass));
    SecureZeroMemory(user, sizeof(user));
    SecureZeroMemory(dom, sizeof(dom));
    return out;
}

/**
 * @brief Encrypt/decrypt all files in a directory tree (skipping '.exe' and 'fence').
 * Decides direction by '.pr$m' extension and renames in place after successful I/O.
 * @tparam SecurePwd Secure password container.
 * @param dir Root directory.
 * @param password Password container.
 * @param recurse Recurse into subdirectories when true.
 * @return true if all processed files succeeded.
 */
template<class SecurePwd>
static bool processFilePathLine(const std::string& raw, const SecurePwd& password);
template<class SecurePwd>
static bool processDirectoryRecursive(const std::string& dir, const SecurePwd& password, bool recurse = true) {
    WIN32_FIND_DATAA fd{};
    std::string pattern = fenc::joinPath(dir, "*");
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "(dir) cannot list: " << dir << "\n";
        return false;
    }

    uint64_t total = 0, ok = 0, fail = 0;
    std::vector<std::future<bool>> futures; // Holds async tasks for file processing

    do {
        const char* name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        std::string full = fenc::joinPath(dir, name);

        if (fenc::endsWithCi(name, ".exe") || _stricmp(name, "fence") == 0) {
            std::cout << "(skipped) " << full << "\n";
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recurse) {
                futures.push_back(std::async(std::launch::async, processDirectoryRecursive<SecurePwd>, full, std::ref(password), true));
            }
            continue;
        }

        futures.push_back(std::async(std::launch::async, processFilePathLine<SecurePwd>, full, std::ref(password)));

        ++total;

    } while (FindNextFileA(h, &fd));

    FindClose(h);

    // Wait for all futures to finish
    for (auto& future : futures) {
        bool result = future.get();
        if (result) ++ok; else ++fail;
    }

    std::cout << "[dir] " << dir << ": " << ok << " ok, " << fail
        << " failed, " << total << " total\n";
    return fail == 0;
}

/**
 * @brief Process a single path or convenience token.
 * - '.' expands to the current directory (recursive).
 * - Directories delegate to @ref processDirectoryRecursive.
 * - Regular files: encrypt to '<name>.pr$m' or decrypt to '<name>' based on extension.
 * - Skips '.exe' and 'fence'.
 * @return true if the line was recognized/handled (success is printed to stdout).
 */
template<class SecurePwd>
static bool processFilePathLine(const std::string& raw, const SecurePwd& password) {
    std::string t = fenc::stripQuotes(fenc::trim(raw));
    if (t.empty()) return false;

    std::string base = fenc::basenameA(t);
    if (fenc::endsWithCi(base, ".exe") || _stricmp(base.c_str(), "fence") == 0) {
        std::cout << "(skipped) " << t << "\n";
        return true;
    }

    if (_stricmp(t.c_str(), ".") == 0) {
        t = std::filesystem::current_path().string();
    }

    if (fenc::isDirectoryA(t)) {
        (void)processDirectoryRecursive(t, password, true);
        return true;
    }

    if (!fenc::fileExistsA(t)) return false;

    const bool isPmg = fenc::endsWithCi(t, ".fence");

    if (isPmg) {
        // Decrypt
        std::string newName = fenc::strip_ext_ci(t, std::string_view{ ".fence" });
        auto fileProcessingFuture = std::async(std::launch::async, decryptFileOverwriteSelf<SecurePwd>, t.c_str(), std::cref(password));
        bool success = fileProcessingFuture.get();

        if (success) {
            // Rename the file after successful decryption
            if (MoveFileExA(t.c_str(), newName.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                std::cout << "(decrypted) " << t << " -> " << newName << "\n";
            }
            else {
                std::cerr << "(decrypt) failed to rename: " << t << " -> " << newName << "\n";
                return false;
            }
        }
        return success;
    }
    else {
        // Encrypt
        std::string newName = fenc::add_ext(t, std::string_view{ ".fence" });
        auto fileProcessingFuture = std::async(std::launch::async, encryptFileOverwriteSelf<SecurePwd>, t.c_str(), std::cref(password));
        bool success = fileProcessingFuture.get();

        if (success) {
            // Rename the file after successful encryption
            if (MoveFileExA(t.c_str(), newName.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                std::cout << "(encrypted) " << t << " -> " << newName << "\n";
            }
            else {
                std::cerr << "(encrypt) failed to rename: " << t << " -> " << newName << "\n";
                return false;
            }
        }
        return success;
    }
}

/**
 * @brief Batch dispatcher for mixed input:
 *  - Paths → encrypt/decrypt/rename,
 *  - Hex tokens → decrypt; if triples, aggregate; else copy plaintext to clipboard (masked mode),
 *  - Other text → encrypt and print hex.
 *
 * If 'uncensored==false', decrypted plaintext is never printed: triples go to an interactive
 * masked view; non-triples are copied to the clipboard for a short TTL and echoed as '*'.
 */
template<class SecurePwd>
static void processBatch(const std::vector<std::string>&lines, bool uncensored, const SecurePwd & password) {
    if (lines.empty()) return;

    std::vector<fenc::secure_triplet16_t> aggTriples;
    std::vector<std::string> otherPlain;
    std::vector<std::string> encHex; // hex outputs for plaintext lines

    for (const auto& L : lines) {
        if (processFilePathLine(L, password)) continue;

        auto hexTokens = fenc::extractHexTokens(L);
        if (!hexTokens.empty()) {
            for (const auto& tok : hexTokens) {
                try {
                    auto plain = decryptLine(tok, password);

                    std::vector<fenc::secure_triplet16<fenc::locked_allocator<wchar_t>>> ts;
                    if (parseTriples(plain.view(), ts)) {
                        aggTriples.insert(aggTriples.end(),
                            std::make_move_iterator(ts.begin()),
                            std::make_move_iterator(ts.end()));
                    }
                    else {
                        (void)fenc::copyWithTTL_any(plain.view());
                        otherPlain.emplace_back(plain.data(), plain.size());
                    }
                    fenc::cleanse_string(plain);
                }
                catch (const std::exception& ex) {
                    std::cerr << "(decrypt failed: " << ex.what() << ")\n";
                }
            }
            continue;
        }

        try {
            encHex.emplace_back(encryptLine(L, password));
        }
        catch (const std::exception& ex) {
            std::cerr << "(encrypt failed: " << ex.what() << ")\n";
        }
    }

    if (!aggTriples.empty()) {
        if (uncensored) {
            std::ostringstream oss;
            for (size_t i = 0; i < aggTriples.size(); ++i) {
                if (i) oss << ", ";
                std::string sv = tripleToUtf8(aggTriples[i]);
                oss << sv;
                fenc::cleanse_string(sv);
            }
            std::cout << oss.str() << "\n";
        }
        else {
            interactiveMaskedWin(aggTriples);
            std::cout << "(Masked; Click **** to copy)\n";
        }
        for (auto& t : aggTriples) {
            fenc::cleanse_string(t.primary, t.secondary, t.tertiary);
        }
    }

    for (auto& p : otherPlain) {
        if (uncensored) {
            std::cout << p << "\n";
        }
        else {
            (void)fenc::copyWithTTL_any(p);
            std::cout << std::string(p.size(), '*') << "  [copied]\n";
        }
        fenc::cleanse_string(p);
    }

    for (const auto& hex : encHex) {
        std::cout << hex << "\n";
    }
}

/**
 * @brief Program entry.
 *
 * Flow:
 *  1. Enable process mitigations and abort under Remote Desktop.
 *  2. Initialize OpenSSL error strings; harden the heap; attempt to enable 'SeLockMemoryPrivilege'.
 *  3. Prompt for a master password via Windows Credentials UI.
 *  4. Optionally process 'fence' first.
 *  5. Enter interactive loop reading batches until '?'/'!'/Esc; dispatch via @ref processBatch.
 *  6. Scrub password and wipe console on exit.
 *
 * @return 0 on normal exit; negative on early security abort.
 */
int main() {
    if (!fenc::set_secure_process_mitigations()) return -1;
    if (fenc::is_remote_session()) return -1;

    fenc::harden_heap();
    if (!fenc::try_enable_lock_privilege()) {
        char* username = nullptr;
        size_t len = 0;
        _dupenv_s(&username, &len, "USERNAME");

        std::cerr << "\n!!! SECURITY WARNING !!!\n\n"
            << "Failed to enable memory lock privilege (SE_LOCK_MEMORY_NAME).\n"
            << "This application cannot securely protect sensitive data in memory.\n\n"
            << "To fix this issue:\n"
            << "  1. Open Group Policy Editor (gpedit.msc)\n"
            << "  2. Go to \"Local Policies\" then \"User Rights Assignment\"\n"
            << "  3. Add your account to \"Lock pages in memory\"\n"
            << "  4. Reboot your system\n\n"
            << "Current user: " << (username ? username : "Unknown") << "\n";

        free(username);  // Must free the memory allocated by _dupenv_s
    }

    try {
        fenc::basic_secure_string<wchar_t> password = readPasswordSecureDesktop();

        // 1) One-off batch from fence (optional)
        {
            std::ifstream fin("fence");
            if (fin) {
                auto fileBatch = readBulkLinesDualFrom(fin);
                const auto& flines = fileBatch.first;
                bool funcensored = fileBatch.second;
                if (!flines.empty()) {
                    processBatch(flines, funcensored, password);
                    std::cout << "\n";
                }
            }
        }

        // 2) Interactive console input
        std::cout << "+-------------------------------------- FenceLock - Interactive Mode --------------------------------------+\n";
        std::cout << "|              Paste/type and finish with '?' (MASKED) or '!' (UNCENSORED) Press Esc to exit.              |\n";
        std::cout << "|    Commands '.'= current dir | ':clip'= copy fence | ':open'= edit fence | ':none'= clear clipboard      |\n";
        std::cout << "+----------------------------------------------------------------------------------------------------------+\n";

        for (;;) {
            std::pair<std::vector<std::string>, bool> batch;
            if (!readBulkLinesDualOrEsc(batch)) {
                // 1) One-off batch from fence (optional)
                {
                    std::ifstream fin("fence");
                    if (fin) {
                        auto fileBatch = readBulkLinesDualFrom(fin);
                        const auto& flines = fileBatch.first;
                        bool funcensored = fileBatch.second;
                        bool yes = false;
                        if (!flines.empty()) {
                            for (auto& line : flines) {
                                if (_stricmp(line.c_str(), ".") == 0 || fenc::isDirectoryA(line.c_str()) || fenc::fileExistsA(line.c_str()))
                                    yes = true;
                            }
                            if (yes)
                                processBatch(flines, funcensored, password);
                            return 0;
                        }
                    }
                }
                return 0; // Esc pressed outside the masked UI
            }
            const auto& lines = batch.first;
            bool uncensored = batch.second;

            if (lines.empty()) break;

            processBatch(lines, uncensored, password);
        }
        fenc::cleanse_string(password);
        fenc::wipeConsoleBuffer();
    }
    catch (const std::exception&) {
        // Interrupted or EOF; exit quietly
    }
    return 0;
}