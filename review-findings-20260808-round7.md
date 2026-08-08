# Code Review Findings — Round 7

## High severity

### 1. Cross-site request forgery can exfiltrate decrypted passwords by SMS
- **File:** `LinuxPass/Controllers/PasswordsController.cs:170-195`
- **Why it matters:** `SendSMS` is a state-changing POST endpoint that decrypts the selected password and forwards it to an external SMS gateway, but it is missing `[ValidateAntiForgeryToken]`. Because the application relies on cookie-based web authentication (`AddDefaultIdentity` and `UseAuthentication()` in `Program.cs`), a malicious site can cause a logged-in operator’s browser to submit this POST automatically. An attacker only needs to know or guess a valid password record id and supply a phone number they control; the server itself will decrypt the stored credential and send it out-of-band.
- **How to fix:** Add CSRF protection to the action and include the antiforgery token in the corresponding form. Consider requiring a fresh confirmation step before transmitting secrets to external systems.

## Medium severity

### 2. Exception details are returned directly to authenticated users from the password details endpoint
- **File:** `LinuxPass/Controllers/PasswordsController.cs:63-80`
- **Why it matters:** when decryption fails, `Details` returns `Problem($"error: {ex}")`, which serializes the full exception text into the HTTP response. In practice this can reveal stack traces, cryptographic failures, malformed ciphertext values, and configuration-dependent details that make later attacks easier. Because this endpoint is used specifically for viewing secrets, the leaked diagnostics are likely to include highly sensitive operational context.
- **How to fix:** Log the exception server-side and return a generic user-facing error message instead of embedding `ex` in the response body.

### 3. Generated passwords are predictable because they use `System.Random`
- **Files:** `LinuxPass/Services/PassGenService.cs:7-39`, `LinuxPass/Controllers/PasswordsController.cs:98`, `LinuxPass/Services/ResetPassService.cs:34`
- **Why it matters:** all account creation and rotation flows depend on `PassGenService.GeneratePassword`, which uses a process-wide `System.Random`. `System.Random` is not cryptographically secure; given enough observations or timing information, generated outputs can be predicted. Here that weakness directly affects newly created Linux account passwords and rotated passwords for all managed hosts.
- **How to fix:** Replace `System.Random` with a cryptographically secure generator such as `RandomNumberGenerator.GetInt32`, and ensure the password policy still guarantees the required character classes.
