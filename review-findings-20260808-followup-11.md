# Code Review Follow-up — 2026-08-08 (Pass 11)

## Scope
Additional review pass focused on authentication-protected controller actions, credential handling, and cryptography. This document intentionally avoids duplicating the findings already captured in `review-findings-20260808-followup-10.md`.

## Findings

### 1. Static zero IV makes password encryption deterministic
- **Severity:** High
- **Location:** `LinuxPass/Services/CryptorService.cs:14-16`, `LinuxPass/Services/CryptorService.cs:35-37`
- **Issue:** `EncryptString` and `DecryptString` force `aesAlg.IV = new byte[16]`, so every encryption operation uses the same all-zero IV with the same padded key.
- **Impact:** Equal plaintext passwords always produce equal ciphertexts. Anyone with database access can identify password reuse across accounts/servers and derive structural information from ciphertext patterns. This also removes semantic security that CBC-mode encryption is expected to provide.
- **Recommendation:** Generate a fresh random IV for every encryption, prepend/store it alongside the ciphertext, and read it back during decryption. Prefer an authenticated construction such as AES-GCM or AES-CBC + HMAC.

### 2. Encryption provides no integrity/authenticity protection
- **Severity:** High
- **Location:** `LinuxPass/Services/CryptorService.cs:10-25`, `LinuxPass/Services/CryptorService.cs:31-44`
- **Issue:** The service performs raw AES encryption/decryption without any MAC or authenticated mode. The application therefore cannot detect if ciphertext stored in the database has been modified.
- **Impact:** An attacker able to tamper with the `Passwords` table can alter encrypted values and cause the application to decrypt attacker-controlled ciphertext. Depending on usage, this can lead to corrupted credentials being displayed, sent over SMS, or pushed to remote systems without any tamper-detection.
- **Recommendation:** Switch to an authenticated encryption scheme (for example `AesGcm`) or pair encryption with an HMAC over IV + ciphertext and verify it before decryption.

### 3. Sensitive exception details are returned to end users
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:77-80`
- **Issue:** `Details` catches all exceptions and returns `Problem($"error: {ex}")`. This serializes the full exception object into the HTTP response.
- **Impact:** Failures in decryption or data access can disclose stack traces, exception types, inner exceptions, file paths, and configuration-dependent details to any authenticated user. That information materially helps follow-on attacks and leaks internals that should stay server-side.
- **Recommendation:** Log the exception server-side and return a generic error message to the client. Avoid including exception objects or stack traces in responses.

### 4. Password rotation is exposed as a state-changing GET endpoint
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:184-203`
- **Issue:** `Rotate(int id)` is a GET action that triggers password resets on remote servers and writes new credentials into the database.
- **Impact:** Because this is a state-changing operation reachable via GET, it can be triggered by simple link navigation, browser prefetching, crawlers, or cross-site request forgery primitives such as an embedded image/link. A victim only needs to be authenticated for an attacker to force password rotation on arbitrary servers.
- **Recommendation:** Change the action to POST-only, add anti-forgery validation, and require an explicit confirmation flow before executing remote password resets.
