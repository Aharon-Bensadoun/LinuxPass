# Code Review Findings — 2026-08-08 (Run 5)

## Scope
Additional repository review focused on controllers, services, views, and deployment guidance.

## Findings

### 1. Any authenticated user can read every stored password and rotate every server account
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:44`, `LinuxPass/Controllers/PasswordsController.cs:164`, `LinuxPass/Controllers/ServersController.cs:186`
- **Why it matters:** The application is a privileged credential vault, but these endpoints do not perform any authorization check beyond whatever global sign-in may exist. Any authenticated user who can reach the app can open `/Passwords/Details/{id}` to decrypt arbitrary credentials, call `/Passwords/SendSMS` to exfiltrate them to a phone number of their choice, and trigger `/Servers/Rotate/{id}` to reset passwords for all discovered accounts on a managed host. This is a direct privilege-escalation and secret-exposure risk.
- **Recommendation:** Protect password viewing, SMS sending, password creation/deletion, and rotation endpoints with explicit role- or policy-based authorization. Enforce object-level authorization before decrypting or sending a password, and log all access to sensitive operations.

### 2. Password encryption uses a static zero IV, making ciphertext deterministic
- **Severity:** high
- **Location:** `LinuxPass/Services/CryptorService.cs:13`, `LinuxPass/Services/CryptorService.cs:32`
- **Why it matters:** `EncryptString` always uses `new byte[16]` as the IV. With AES this means identical plaintext encrypted with the same key always produces identical ciphertext. An attacker with database access can identify reused passwords, correlate resets, and infer operational behavior. The scheme also lacks an integrity check, so tampered ciphertext may only fail late during decryption.
- **Recommendation:** Switch to an authenticated encryption scheme with a random nonce/IV per secret, such as AES-GCM, and store the nonce alongside the ciphertext. If AES-CBC must be kept temporarily, generate a cryptographically random IV per record and add an HMAC for integrity.

### 3. SMS sending leaks plaintext credentials in the query string of a GET request
- **Severity:** high
- **Location:** `LinuxPass/Services/SendSMSService.cs:19-29`
- **Why it matters:** The SMS gateway request appends the decrypted password directly into the URL. Query strings are routinely captured by reverse proxies, application logs, browser history, monitoring systems, and third-party infrastructure. In addition, only the static message prefix is URL-encoded; the password itself is concatenated afterwards, so special characters can corrupt the request or be interpreted as additional parameters.
- **Recommendation:** Do not transmit credentials through GET query strings. Prefer a POST request with a structured body, URL-encode or serialize the full message payload, and avoid sending passwords over SMS unless there is a formally accepted risk exception.

### 4. Documentation publishes a reusable certificate password and weakens the SSH private key permissions
- **Severity:** medium
- **Location:** `README.md:95-96`, `README.md:131`
- **Why it matters:** The deployment instructions hard-code the certificate password `A123456a` in both the `openssl pkcs12` example and the `docker run` command. Operators frequently copy these examples verbatim, which normalizes a known secret across environments. The same script then sets `/app/id_rsa` to mode `754`, making the private key readable by group and others inside the container. That broadens the blast radius if another process or user lands in the container.
- **Recommendation:** Replace the sample password with a placeholder sourced from a secret store or environment variable, and document least-privilege file modes such as `600` for private keys.
