# FenceLock AES-256-GCM Console Utility

**FenceLockis** a powerful **AES-256-GCM Encryption/Decryption** console utility designed to securely handle files and inline text. It uses a robust memory protection mechanism, ensuring sensitive data is securely locked, scrubbed, and protected from unauthorized access.

## Features

- **AES-256-GCM Encryption/Decryption**: Securely encrypt and decrypt files and text.

- **Secure Memory Allocation**: Sensitive data is stored in locked memory regions with guard pages and a canary to prevent overflows and unauthorized access.
  
- **Windows Security Mitigations**: Several Windows mitigations are applied, including restrictions on dynamic code execution, strict handle checks, and signed-image loading preferences.

### Prerequisites

- **OpenSSL 3.x**: Ensure you have OpenSSL version 3.x installed on your system to build and use the tool.
