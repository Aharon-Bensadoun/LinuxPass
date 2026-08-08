# Code Review Follow-up 7

## Findings

### 1. Critical — Password encryption is deterministic and uses a zero IV
- **Location:** `LinuxPass/Services/CryptorService.cs:11-35`
- **Issue:** `EncryptString` derives the AES key by padding/truncating the configured string and always sets `aesAlg.IV = new byte[16]`.
- **Why it matters:** Re-encrypting the same plaintext with the same key always produces the same ciphertext. Because this application stores many generated passwords in the database, an attacker who gets read access can correlate identical passwords across accounts/servers, and the static IV removes an essential security property of AES-CBC-style encryption. This is a real confidentiality weakness, not just a style issue.
- **Recommendation:** Generate a fresh random IV per encryption, prepend/store it with the ciphertext, and use a proper key derivation mechanism or a binary key loaded from configuration/secret storage instead of ad-hoc string padding.

### 2. High — Remote shell commands interpolate untrusted usernames without escaping
- **Location:** `LinuxPass/Services/AddUserService.cs:21`, `LinuxPass/Services/ResetPassService.cs:35-38`
- **Issue:** The application builds shell commands with string interpolation, for example:
  - `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  - `echo '{user}:{password}' | sudo chpasswd`
- **Why it matters:** `username` comes from user input in `PasswordsController.Create`, and `user` in rotation comes from remote command output. Either value can contain shell metacharacters or quotes that break the command structure. In the create flow, a malicious operator can inject arbitrary commands on the managed server with the privileges of the SSH account (which is explicitly granted broad sudo access elsewhere in the code). In the rotation flow, a specially named account on the remote host can break or hijack the reset command.
- **Recommendation:** Strictly validate account names against an allowlist such as POSIX username rules before use, and avoid shell interpolation by passing data through safer mechanisms (e.g. argument escaping designed for the target shell, or a script that reads structured input).

### 3. Medium — Password rotation accumulates duplicate historical secrets and the UI may expose stale passwords
- **Location:** `LinuxPass/Services/ResetPassService.cs:41-51`, `LinuxPass/Controllers/PasswordsController.cs:36-39`
- **Issue:** Every rotation inserts a new `Password` row for the same `(Username, Servername)` pair, but older rows are never invalidated or deleted. The index view later groups duplicates and keeps only the newest record, yet direct access by old `Id` values still works in `Details` and reveals the previous decrypted password.
- **Why it matters:** Anyone who bookmarked, logged, or otherwise retained an old details URL can continue retrieving superseded credentials long after a rotation. That undermines the security benefit of password rotation and grows the database indefinitely with recoverable old secrets.
- **Recommendation:** Replace the existing record instead of appending, or mark prior rows inactive and ensure details endpoints reject non-current credentials.
