# Code review findings

## 1. Critical — OS command injection in SSH command construction
- **Where:** `LinuxPass/Services/AddUserService.cs`, `LinuxPass/Services/AddServerService.cs`, `LinuxPass/Services/ResetPassService.cs`
- **Why:** User-controlled or database-controlled values such as `username`, `password`, `hostname`, and SSH public key material are interpolated directly into shell commands executed remotely via `client.CreateCommand(...)`.
- **Impact:** An attacker who can submit crafted usernames/server values could execute arbitrary commands on managed servers, potentially resulting in full remote compromise.
- **Evidence:** Examples include:
  - `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  - `echo '{username} ALL=(ALL) NOPASSWD:ALL' | ...`
  - `echo '{user}:{password}' | sudo chpasswd`
- **Recommendation:** Avoid shell interpolation entirely. Use SSH subsystems/APIs that pass arguments safely, or strictly validate/escape every interpolated value against an allowlist (for example, POSIX username character set only). Treat SSH key contents as untrusted data as well.

## 2. High — Passwords are encrypted with a static zero IV and no integrity protection
- **Where:** `LinuxPass/Services/CryptorService.cs`
- **Why:** `Aes.Create()` is used with `aesAlg.IV = new byte[16]`, meaning every password encrypted with the same key uses the same IV. The code also lacks authentication/integrity protection (for example AES-GCM or encrypt-then-MAC).
- **Impact:** Encryption is deterministic, so identical plaintext passwords produce identical ciphertexts, leaking password reuse patterns. Without integrity protection, ciphertext tampering may go undetected and could lead to corrupted or attacker-controlled decrypted values.
- **Recommendation:** Use an authenticated encryption scheme such as AES-GCM, generating a fresh random nonce/IV for every encryption and storing it alongside the ciphertext.

## 3. High — Sensitive passwords are disclosed in the UI and can be exfiltrated through SMS workflow
- **Where:** `LinuxPass/Controllers/PasswordsController.cs`, `LinuxPass/Views/Passwords/Details.cshtml`
- **Why:** The application decrypts and renders stored passwords back to the browser in `Details`, placing the cleartext secret into the HTML response (`value="@Model.DecryptedPassword"`). Any user with access to the page, browser extensions, DOM inspection, caches, or screenshots can recover it.
- **Impact:** This defeats the value of storing passwords encrypted at rest and greatly expands the exposure surface of every managed credential.
- **Recommendation:** Avoid rendering full passwords by default. Prefer one-time privileged reveal flows with re-authentication, tight authorization checks, audit logging, masking, and short-lived server-side retrieval.

## 4. Medium — SMS API request leaks secrets in URL query parameters
- **Where:** `LinuxPass/Services/SendSMSService.cs`
- **Why:** The plaintext password is appended to a GET URL query string: `...?SMSMessage=...{decryptedPassword}&SMSPhone=...`. Query strings are commonly logged by servers, proxies, APM tools, browser history, and upstream infrastructure.
- **Impact:** Managed account passwords may be exposed outside the application boundary through logs and network tooling.
- **Recommendation:** Do not send secrets in URLs. If SMS delivery is required at all, use a POST body over TLS and avoid transmitting reusable passwords over SMS.

## 5. Medium — Password rotation is exposed as a GET action, enabling CSRF on a state-changing operation
- **Where:** `LinuxPass/Controllers/ServersController.cs`
- **Why:** `Rotate(int id)` performs password resets and database writes but is exposed without `[HttpPost]` and without anti-forgery validation.
- **Impact:** A malicious site could cause an authenticated user’s browser to trigger password rotation unintentionally, creating operational disruption and unexpected credential changes.
- **Recommendation:** Change this to POST only, require anti-forgery validation, and consider re-authentication/confirmation for credential-rotation actions.

## 6. Medium — SMS sending endpoint lacks anti-forgery validation
- **Where:** `LinuxPass/Controllers/PasswordsController.cs`, action `SendSMS`
- **Why:** The action is `[HttpPost]` but does not use `[ValidateAntiForgeryToken]`, while the corresponding form posts directly from the browser.
- **Impact:** An attacker could induce an authenticated victim to send stored credentials to an attacker-controlled phone number.
- **Recommendation:** Add anti-forgery validation and ensure the form emits the token. Consider tighter authorization and audit logging for password-sharing actions.
