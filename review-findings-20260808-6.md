# Code Review Findings

## High — Remote command injection via unsanitized username in SSH commands
- **Files:** `LinuxPass/Services/AddUserService.cs:25`, `LinuxPass/Services/AddServerService.cs:24`
- **Issue:** User-controlled values are interpolated directly into shell commands executed over SSH without any quoting or validation.
- **Why this matters:** `password.Username` is user input from `PasswordsController.Create`, and `server.HostSrvUsername` is user input from `ServersController.Create/Edit`. An authenticated user can supply shell metacharacters (for example `;`, backticks, `$()`) and cause arbitrary commands to execute on the managed Linux host as the SSH user, which is then combined with `sudo` operations.
- **Evidence:**
  - `AddUserService` runs `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  - `AddServerService` runs `echo '{username} ALL=(ALL) NOPASSWD:ALL' ...` and writes to `/etc/sudoers.d/{username}`
- **Impact:** Arbitrary command execution on target servers, including likely privilege escalation to root because the injected commands are embedded in privileged `sudo` flows.
- **Recommendation:** Do not build shell commands through string interpolation. Strictly validate allowed usernames/hostnames against a safe regex and pass arguments through APIs that avoid a shell, or escape every argument robustly for the remote shell.

## High — Stored passwords use deterministic AES encryption with a fixed zero IV
- **File:** `LinuxPass/Services/CryptorService.cs:14-16`, `LinuxPass/Services/CryptorService.cs:35-37`
- **Issue:** Passwords are encrypted with AES using a key derived by padding/truncating configuration text, and the IV is always `new byte[16]`.
- **Why this matters:** Reusing a constant IV makes encryption deterministic: identical plaintexts encrypted with the same key produce identical ciphertexts. This leaks password reuse patterns across accounts and servers. The construction also lacks explicit integrity protection, so ciphertext tampering is not safely detected with an authenticated mode.
- **Impact:** Confidentiality is weakened for all stored passwords, and database compromise exposes structural information about repeated secrets.
- **Recommendation:** Use a modern authenticated encryption scheme with a fresh random nonce/IV per record, such as AES-GCM, and store the nonce alongside the ciphertext. Derive the key from a proper secret source rather than padding arbitrary text.

## Medium — Passwords are exfiltrated via query string to the SMS gateway
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:180-193`, `LinuxPass/Services/SendSMSService.cs:18-27`
- **Issue:** The application decrypts the stored password and appends it directly into a GET request URL sent to the SMS API.
- **Why this matters:** Query strings are routinely exposed in proxy logs, server logs, browser/network tooling, and monitoring systems. Even if HTTPS is used, the plaintext password is still propagated to every component that records the full request URL.
- **Impact:** Any password sent through this flow is likely disclosed outside the application boundary to log stores and third-party providers.
- **Recommendation:** Do not transmit passwords in URL query parameters. If this feature must exist, use a POST body over TLS and minimize downstream logging; ideally avoid sending reusable credentials over SMS entirely.
