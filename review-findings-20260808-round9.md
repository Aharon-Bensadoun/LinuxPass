# Code review findings — round 9

## 1. Remote command injection when creating Linux users
- **Severity:** high
- **Location:** `LinuxPass/Services/AddUserService.cs:25`
- **Issue:** `username` and `password` are interpolated directly into a shell command executed over SSH:
  ```csharp
  client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd")
  ```
  The controller accepts `password.Username` from the request (`LinuxPass/Controllers/PasswordsController.cs:96-119`) without any server-side validation restricting it to safe Unix account characters. A crafted username containing shell metacharacters can break out of the intended command and execute arbitrary commands on the managed server with the SSH account's privileges.
- **Recommendation:** Never compose shell commands with raw user input. Validate usernames against a strict allowlist (for example `^[a-z_][a-z0-9_-]*[$]?$`), and pass data through a safer mechanism such as a script with positional arguments that are correctly shell-escaped, or an API/provisioning layer that avoids shell parsing entirely.

## 2. Stored passwords are encrypted with deterministic AES and no integrity protection
- **Severity:** high
- **Location:** `LinuxPass/Services/CryptorService.cs:14-16`, `LinuxPass/Services/CryptorService.cs:35-37`
- **Issue:** The encryption code derives the AES key by truncating/padding a config string and always uses an all-zero IV. This makes encryption deterministic: identical plaintext passwords under the same key produce identical ciphertexts. It also provides no authentication tag/MAC, so ciphertext tampering is not detected before decryption.
- **Impact:** An attacker with database access can identify password reuse patterns across accounts, and modified ciphertext can lead to corrupted plaintext or decryption-oracle style behavior.
- **Recommendation:** Replace this with an authenticated encryption scheme using a random per-record nonce/IV, e.g. AES-GCM or AES-CBC plus HMAC with separate keys. Store the nonce alongside the ciphertext and derive keys with a proper KDF rather than `PadRight(...).Substring(...)`.

## 3. Generated passwords are predictable and low-entropy by construction
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:98`, `LinuxPass/Services/PassGenService.cs:7-39`
- **Issue:** New passwords are generated with `Complexity.Low`, which limits the alphabet to lowercase letters only, and the generator uses `System.Random`, which is not cryptographically secure. The resulting 12-character passwords are both easier to brute force and potentially predictable from RNG state.
- **Recommendation:** Use `RandomNumberGenerator`/`GetInt32` for password generation and require a stronger policy that includes upper/lowercase, digits, and optionally symbols, with guaranteed inclusion of each required character class.

## 4. Passwords are sent in the SMS provider URL query string
- **Severity:** high
- **Location:** `LinuxPass/Services/SendSMSService.cs:25`, `LinuxPass/Controllers/PasswordsController.cs:193`
- **Issue:** The decrypted password is appended directly into the request URL query string when calling the SMS gateway. Query strings are routinely logged by reverse proxies, application logs, browser history, monitoring systems, and third-party providers. In addition, only the static message prefix is URL-encoded; the password and phone number are not encoded before concatenation.
- **Recommendation:** Do not send secrets in URLs. If SMS delivery is unavoidable, place parameters in an HTTPS POST body and encode every field separately. Prefer sending a one-time retrieval link or reset token instead of the actual password.

## 5. Full exception details are returned to end users during password decryption
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:78-80`
- **Issue:** The `Details` action returns `Problem($"error: {ex}")`, which exposes the full exception object to the client. This can leak stack traces, key/formatting failures, and internal implementation details useful for attackers.
- **Recommendation:** Log the exception server-side and return a generic error message to the user. Avoid including raw exception text in HTTP responses.
