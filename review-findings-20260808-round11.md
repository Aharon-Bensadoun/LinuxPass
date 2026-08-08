# Code Review Findings — Round 11

## High severity

1. **Passwords are generated with only lowercase letters for newly created users**
   - **Location:** `LinuxPass/Controllers/PasswordsController.cs:98`, `LinuxPass/Services/PassGenService.cs:19-39`
   - **Issue:** `PasswordsController.Create` generates credentials with `PassGenService.Complexity.Low`, and that implementation uses only the `Lowercase` alphabet. Every manually created Linux account therefore receives a 12-character password made exclusively of lowercase letters.
   - **Impact:** This shrinks the search space dramatically versus a mixed-case/alphanumeric/symbol password and makes the initial credentials far easier to brute-force or guess. Because the application stores and displays these passwords for operational use, these weak passwords are not merely temporary random tokens; they are the actual server credentials being provisioned.
   - **Recommendation:** Use a cryptographically secure generator and require at least the same complexity level already used in `ResetPassService` (`High`), preferably with guaranteed inclusion of multiple character classes.

2. **Encryption is deterministic because AES uses a fixed all-zero IV**
   - **Location:** `LinuxPass/Services/CryptorService.cs:14-16`, `LinuxPass/Services/CryptorService.cs:35-37`
   - **Issue:** `EncryptString` and `DecryptString` derive the AES key by padding/truncating config text and then always set `aesAlg.IV = new byte[16]`. Reusing the same IV for every encryption makes the scheme deterministic: identical plaintext passwords encrypt to identical ciphertexts.
   - **Impact:** Anyone with database access can immediately tell when two users or two rotations share the same password value, which leaks sensitive information and weakens confidentiality. With CBC/CTR-style modes, fixed-IV reuse is a standard cryptographic flaw.
   - **Recommendation:** Generate a fresh random IV per encryption, store it alongside the ciphertext, and use a proper KDF for the configured secret rather than UTF-8 padding/truncation.

3. **Usernames and passwords are interpolated directly into privileged shell commands**
   - **Location:** `LinuxPass/Services/AddUserService.cs:25`, `LinuxPass/Services/AddServerService.cs:24,34`, `LinuxPass/Services/ResetPassService.cs:39`
   - **Issue:** Remote commands are built with string interpolation and shell metacharacters are not escaped. User-controlled values such as `password.Username`, server usernames, generated passwords, and SSH public-key contents are inserted directly into `sudo useradd`, `chpasswd`, `visudo`, and shell redirections.
   - **Impact:** A crafted username or other injected value can break the command syntax or execute arbitrary shell fragments on the managed Linux servers under elevated privileges. This is a direct remote command injection path in the app’s highest-risk code paths.
   - **Recommendation:** Avoid shell concatenation entirely where possible. Pass data through safe APIs or strictly validate/escape every interpolated field against an allowlist (for example, Linux usernames matching `^[a-z_][a-z0-9_-]*[$]?$`).
