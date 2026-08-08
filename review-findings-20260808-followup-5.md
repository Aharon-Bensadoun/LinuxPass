# Code review findings — follow-up 5

## 1. Command injection in SSH provisioning flows
- **Severity:** High
- **Locations:** `LinuxPass/Services/AddServerService.cs:24`, `LinuxPass/Services/AddServerService.cs:34`, `LinuxPass/Services/AddUserService.cs:25`, `LinuxPass/Services/ResetPassService.cs:39`
- **Issue:** User-controlled or externally sourced values (`username`, `password`, `pubkey`, `user`) are interpolated directly into shell commands executed over SSH. Single quotes do not make this safe because an input containing a quote can terminate the intended shell string and inject arbitrary commands.
- **Impact:** An attacker who can create or influence usernames, passwords, or SSH key contents can execute arbitrary commands on managed servers with the privileges of the SSH session, including `sudo` paths already used by the application.
- **Recommendation:** Stop building shell commands through string interpolation. Either use a safer remote execution strategy that passes arguments without shell parsing, or strictly validate and escape every argument with a hardened shell-escaping routine and reject unexpected characters. In practice, usernames should be restricted to a conservative allowlist such as POSIX-safe account names.

## 2. Password history remains readable after server deletion
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/ServersController.cs:196`
- **Issue:** `ServersController.DeleteConfirmed` removes only the `Server` row. It does not delete related `Password` entries for the same host.
- **Impact:** After deleting a server from the inventory, historical passwords for that host remain in the database and continue to be exposed in the UI and SMS flow. This violates user expectations and increases retention of sensitive credentials beyond their operational lifetime.
- **Recommendation:** Delete or securely archive associated password records when a server is removed, and define explicit retention behavior for historical credentials.

## 3. Deterministic encryption leaks password equality and lacks semantic security
- **Severity:** High
- **Location:** `LinuxPass/Services/CryptorService.cs:10-39`
- **Issue:** AES is used with a zero IV (`aesAlg.IV = new byte[16]`) for every encryption. This makes encryption deterministic for identical plaintext under the same key.
- **Impact:** Anyone with database access can identify reused passwords across accounts or over time by comparing ciphertexts, and the scheme does not provide modern semantic security expectations for stored secrets.
- **Recommendation:** Use a random IV/nonce per encryption and store it alongside the ciphertext, or better yet use an authenticated encryption mode such as AES-GCM. If the product only needs temporary disclosure rather than recovery, reconsider whether reversible encryption is required at all.

## 4. Sensitive secret is appended to outbound URL without encoding
- **Severity:** Medium
- **Location:** `LinuxPass/Services/SendSMSService.cs:23`
- **Issue:** Only the static message prefix is URL-encoded. The decrypted password is concatenated afterward into the query string without encoding.
- **Impact:** Passwords containing characters such as `&`, `=`, `+`, `#`, or `%` can alter the query structure, truncate the transmitted secret, or inject unintended parameter values into the SMS provider request. This can also cause secret leakage in provider-side logs under malformed parameter boundaries.
- **Recommendation:** URL-encode the complete message after concatenating all message content, or build the query string through a proper URI/query builder so every parameter value is encoded exactly once.

## 5. Rotation workflow can report success even when remote password resets fail
- **Severity:** Medium
- **Location:** `LinuxPass/Services/ResetPassService.cs:39-56`
- **Issue:** Inside the rotation loop, the code executes `chpasswd` but never checks `command.ExitStatus` or `command.Error` before writing the newly encrypted password to the database and continuing.
- **Impact:** The application can persist credentials that were never actually applied on the target server, creating a false sense of successful rotation and potentially locking operators out with incorrect records.
- **Recommendation:** Validate the result of each remote command before persisting the new password, and make the reset/database update atomic per user as much as possible. If a reset fails, do not store the generated password as authoritative.
