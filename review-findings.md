# Review findings

## 1. Password encryption is deterministic and lacks integrity protection
- **Severity:** high
- **Location:** `LinuxPass/Services/CryptorService.cs`
- **Issue:** `EncryptString` and `DecryptString` derive the AES key by truncating/padding the configured secret and always use an all-zero IV (`aesAlg.IV = new byte[16]`). This makes encryption deterministic: identical passwords always produce identical ciphertexts. The implementation also provides no authentication tag or MAC, so ciphertext tampering is not detected reliably.
- **Impact:** Anyone with database access can spot password reuse across accounts/servers, and modified ciphertext may decrypt to attacker-controlled garbage without a cryptographic integrity check. Because this application stores privileged credentials, deterministic unauthenticated encryption is a significant risk.
- **Recommendation:** Replace this with an authenticated encryption scheme using a random nonce/IV per record (for example AES-GCM, or AES-CBC + HMAC if GCM is unavailable). Store the nonce alongside the ciphertext, and derive keys with a proper KDF instead of padding/truncating the configuration value.

## 2. SSH commands are built from untrusted input, enabling command injection on managed servers
- **Severity:** high
- **Locations:** `LinuxPass/Services/AddUserService.cs`, `LinuxPass/Services/ResetPassService.cs`, `LinuxPass/Services/AddServerService.cs`
- **Issue:** Multiple shell commands interpolate untrusted values directly into command strings executed over SSH:
  - `AddUserService`: `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  - `ResetPassService`: `echo '{user}:{password}' | sudo chpasswd`
  - `AddServerService`: writes `username` and the configured public key into shell commands without escaping
- **Impact:** A crafted username, hostname-derived account name, or malformed key content can break quoting and inject arbitrary shell syntax. Because these commands run with `sudo`, successful injection would allow arbitrary privileged command execution on the managed server.
- **Recommendation:** Never compose shell commands with raw interpolation. Validate usernames against a strict allowlist (for example POSIX account-name rules), escape shell arguments correctly, or better yet avoid shell composition entirely by using safer primitives/APIs for account management.

## 3. Password rotation is exposed as a GET endpoint without anti-forgery protection
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/ServersController.cs`
- **Issue:** `Rotate(int id)` performs a state-changing action (resetting passwords on a server and inserting new credentials into the database) but is implemented as a GET action and linked directly from the index page.
- **Impact:** Any page visited by an authenticated user can trigger password rotation via a forged image/link request. This is a classic CSRF issue and can rotate credentials unexpectedly, causing operational disruption and forced password disclosure workflows.
- **Recommendation:** Restrict the action to POST only, add `[ValidateAntiForgeryToken]`, and invoke it from a form/button instead of a plain link.

## 4. SMS sending leaks credentials in the request URL
- **Severity:** medium
- **Location:** `LinuxPass/Services/SendSMSService.cs`
- **Issue:** The SMS API call is sent as an HTTP GET with the decrypted password appended in the query string: `...?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone=...`.
- **Impact:** Query strings are commonly logged by application servers, reverse proxies, outbound proxies, browser history, monitoring tools, and third-party providers. This design leaks plaintext passwords to systems far beyond the intended SMS recipient.
- **Recommendation:** Do not place secrets in URLs. Use a POST request with the sensitive payload in the body, and confirm the downstream provider/API is designed for secret transport. More fundamentally, reconsider whether sending privileged passwords over SMS is acceptable at all.
