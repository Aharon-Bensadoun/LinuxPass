# Code Review Findings — 2026-08-08 (Run 6)

## Scope
Targeted review of the LinuxPass repository after the previous review run. This pass focused on controller flows, credential handling, SSH command construction, SMS delivery, and deployment guidance.

## Findings

### 1. Critical — Remote command injection via unsanitized usernames/passwords in SSH commands
- **Files:** `LinuxPass/Services/AddUserService.cs:21`, `LinuxPass/Services/ResetPassService.cs:36`
- **What happens:** User-controlled values are interpolated directly into shell commands executed over SSH:
  - `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  - `echo '{user}:{password}' | sudo chpasswd`
- **Why this is dangerous:** The application accepts usernames from web requests and also consumes usernames discovered from remote host output. A username containing shell metacharacters or a single quote can break command quoting and execute arbitrary commands on the managed Linux server with elevated privileges.
- **Impact:** Full command execution on target servers; account takeover or host compromise.
- **Recommendation:** Avoid shell interpolation entirely. Pass data through a safe channel (for example, upload a script with validated arguments, or strictly validate usernames against a conservative allowlist such as `^[a-z_][a-z0-9_-]{0,31}$` and escape every shell argument with a dedicated routine).

### 2. High — Stored passwords are encrypted with deterministic AES using a zero IV
- **File:** `LinuxPass/Services/CryptorService.cs:11`
- **What happens:** AES is used with a key derived by padding/truncating the configured string, and the IV is always `new byte[16]`.
- **Why this is dangerous:** Reusing a fixed IV makes encryption deterministic. Identical passwords encrypted under the same key produce identical ciphertexts, leaking equality patterns and weakening confidentiality. Padding/truncation is also not a proper key derivation strategy.
- **Impact:** Password pattern disclosure across accounts/servers and reduced resistance if the database is exposed.
- **Recommendation:** Use authenticated encryption with a random IV/nonce per record and store it alongside the ciphertext. Derive keys with a proper KDF or load a fixed-length secret from secure configuration in binary form.

### 3. High — Password disclosure through GET query string to external SMS API
- **File:** `LinuxPass/Services/SendSMSService.cs:20`
- **What happens:** The decrypted password is appended to a URL and sent via `HttpClient.GetAsync(url)`.
- **Why this is dangerous:** Query strings are commonly logged by reverse proxies, load balancers, browser history, monitoring tools, and the receiving service itself. This leaks plaintext credentials far beyond the application boundary.
- **Impact:** Plaintext password exposure in logs and third-party systems.
- **Recommendation:** Do not transmit passwords over SMS. If message delivery is unavoidable, use a POST body over TLS and ensure secrets never appear in URLs or logs. Prefer one-time links or OTP-based recovery flows instead of sending reusable credentials.

### 4. Medium — Detailed exception text is returned to end users from password details flow
- **File:** `LinuxPass/Controllers/PasswordsController.cs:73`
- **What happens:** The `Details` action catches any exception and returns `Problem($"error: {ex}")`.
- **Why this is dangerous:** Raw exception details can expose stack traces, crypto failures, configuration mistakes, and internal object state to authenticated users.
- **Impact:** Information disclosure that can help an attacker understand the environment and failure modes.
- **Recommendation:** Log the exception server-side and return a generic user-facing error message.

### 5. Medium — Deployment instructions encourage shipping private keys and a hard-coded certificate password
- **File:** `README.md:122`
- **What happens:** The deployment script copies `.ssh/id_rsa` into the container and uses a literal PFX password `A123456a` in example commands/environment variables.
- **Why this is dangerous:** Baking operational secrets into deployment steps normalizes insecure handling and increases the chance that private keys or certificate passwords are reused, leaked, or committed elsewhere.
- **Impact:** Credential exposure and weakened container hardening.
- **Recommendation:** Mount secrets from a dedicated secret store or host-protected volume, generate per-environment credentials, and remove hard-coded example passwords from the deployment guidance.

## Validation
- `dotnet build LinuxPass.sln` ✅
  - Build succeeds.
  - Existing warnings remain:
    - `NU1902` on `Microsoft.Identity.Web` 3.7.0
    - `CS8602` in `Views/Shared/_Layout.cshtml`
    - `CS8602` in `Views/Passwords/Details.cshtml`
