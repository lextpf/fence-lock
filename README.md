# **FenceLock AES-256-GCM Console Utility** 🔐

**FenceLock** is a robust **AES-256-GCM Encryption/Decryption** console utility, designed to **securely handle files and inline text**. With state-of-the-art memory protection mechanisms, it ensures that sensitive data is **locked, scrubbed, and shielded** from unauthorized access, making it an essential tool for anyone prioritizing security.

## **🛠️ Features**

* **🔒 AES-256-GCM Encryption/Decryption**
  Securely encrypt and decrypt both files and inline text with industry-standard AES-256-GCM encryption.

* **💾 Secure Memory Allocation**
  Sensitive data is stored in **locked memory** regions, fortified with **guard pages** and a **canary** to prevent overflows and unauthorized access.

* **🛡️ Windows Security Mitigations**
  Multiple security layers are applied, including:

  * **Restrictions on dynamic code execution**
  * **Strict handle checks**
  * **Signed-image loading preferences**
    
## **🔧 Prerequisites**

Before using the utility, ensure you have the following installed:

* **OpenSSL 3.x**: Required to build and operate **FenceLock**. Please install OpenSSL version 3.x on your system.


