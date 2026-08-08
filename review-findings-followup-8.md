# Code Review Findings — Follow-up 8

## 1. Password decryption endpoint exposes every stored secret to any authenticated user
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:50`
- **Issue:** `Details(int? id)` decrypts the stored password and returns it to the view for any authenticated caller. The application config in `Program.cs` only enforces authentication globally; it does not restrict access by role, group, owner, or server scope. As a result, any signed-in user who can guess or enumerate a password id can retrieve plaintext credentials for arbitrary accounts and servers.
- **Why it matters:** This is a direct confidentiality break for the system’s primary secret store.
- **Suggested fix:** Restrict password viewing to an authorized admin/operator role, and enforce object-level authorization before decrypting or returning the secret.

## 2. Remote shell commands interpolate untrusted input directly
- **Severity:** high
- **Location:** `LinuxPass/Services/AddUserService.cs:22`, `LinuxPass/Services/ResetPassService.cs:38`, `LinuxPass/Services/AddServerService.cs:23`
- **Issue:** SSH commands are composed with string interpolation and include untrusted values such as `username`, generated passwords, and configured public key contents directly inside shell command strings. For example, `AddUserService` executes `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd` without any shell escaping or validation of `username`.
- **Why it matters:** A crafted username or other injected value containing shell metacharacters or quotes can alter the command executed on the remote host, leading to privilege escalation or arbitrary command execution.
- **Suggested fix:** Strictly validate server/user identifiers against an allowlist of accepted characters, and avoid shell interpolation for secrets/arguments. Use safer command construction, argument escaping, or upload-and-execute scripts with fixed parameters.

## 3. Stored passwords are encrypted with a static zero IV
- **Severity:** medium
- **Location:** `LinuxPass/Services/CryptorService.cs:13-14`, `LinuxPass/Services/CryptorService.cs:33-34`
- **Issue:** AES encryption always uses `aesAlg.IV = new byte[16]`. This makes encryption deterministic for identical plaintexts under the same key.
- **Why it matters:** Two identical passwords encrypt to the same ciphertext, leaking password reuse patterns across accounts and rotations. It also departs from standard secure usage of CBC/CTR-style symmetric encryption, where each encryption must use a fresh random IV/nonce.
- **Suggested fix:** Generate a random IV for each encryption, store it alongside the ciphertext, and authenticate the ciphertext with an AEAD mode such as AES-GCM or with an HMAC.

## 4. SMS password delivery uses a GET URL containing the plaintext password
- **Severity:** high
- **Location:** `LinuxPass/Services/SendSMSService.cs:24`
- **Issue:** `SendSMSAsync` appends `decryptedPassword` directly into the query string of a GET request. Query strings are commonly logged by reverse proxies, app telemetry, browser/network tooling, and third-party API infrastructure.
- **Why it matters:** Even if SMS sending is intended, this implementation leaks the password to additional systems beyond the final recipient, significantly expanding exposure of plaintext credentials.
- **Suggested fix:** Do not send credentials in query strings. Prefer not transmitting passwords over SMS at all; otherwise use a POST body over TLS and minimize logging at every hop.
