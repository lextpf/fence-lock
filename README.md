**# FenceLock AES-256-GCM Console Utility**



**\*\*FenceLock\*\* is a powerful AES-256-GCM encryption/decryption console utility designed to securely handle files and inline text. It uses a robust memory protection mechanism, ensuring sensitive data is securely locked, scrubbed, and protected from unauthorized access.**



**## Features**



**- \*\*AES-256-GCM Encryption/Decryption\*\*: Securely encrypt and decrypt files and text.**

**- \*\*Secure Memory Allocation\*\*: Sensitive data is stored in locked memory regions with guard pages and a canary to prevent overflows and unauthorized access.**

**- \*\*Automatic Key Derivation\*\*: Keys are derived from a password using scrypt with a unique, random 16-byte salt for each operation.**

**- \*\*Windows Security Mitigations\*\*: Several Windows mitigations are applied, including restrictions on dynamic code execution, strict handle checks, and signed-image loading preferences.**

**- \*\*Custom Allocator\*\*: Uses a custom allocator that reserves memory with `PAGE\_NOACCESS` guard pages, locks committed pages, and scrubs memory on deallocation.**

**- \*\*Canary for Buffer Overruns\*\*: Detects buffer overruns with a 0xD0 canary placed at the end of allocations.**

**- \*\*Guard Pages\*\*: Implements guard pages on both sides of the allocated memory to further protect against accidental access.**

**- \*\*Clipboard Scrubbing\*\*: Automatically scrubs sensitive data from the clipboard after a short TTL (time-to-live).**



**## Installation**



**### Prerequisites**



**- \*\*OpenSSL 3.x\*\*: Ensure you have OpenSSL version 3.x installed on your system to build and use the tool.**



**### Build Instructions**



**To compile \*\*FenceLock\*\*, you will need a C++ compiler that supports C++17 or higher, as well as the OpenSSL library.**



**1. Clone the repository:**

   **```bash**

   **git clone https://github.com/yourusername/fencelock.git**

   **cd fencelock**



