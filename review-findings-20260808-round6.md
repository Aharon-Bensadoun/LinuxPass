# Code Review Findings — Round 6

## Finding 1 — Remote shell command injection in account creation and password rotation

**Severity:** High

**Where:** `LinuxPass/Services/AddUserService.cs:25`, `LinuxPass/Services/ResetPassService.cs:39`, `LinuxPass/Services/AddServerService.cs:24,34`

**Why this matters:**
User-controlled or remotely sourced values are interpolated directly into shell commands executed over SSH. In `AddUserService`, both `username` and `password` are inserted into `sudo useradd ... && echo '{username}:{password}' | sudo chpasswd`. In `ResetPassService`, each remote username discovered from `/etc/passwd` is inserted into `echo '{user}:{password}' | sudo chpasswd`. In `AddServerService`, `username` is injected into both `visudo` and `/etc/sudoers.d/{username}`, and the configured public key contents are injected into a shell `echo` command.

Because these values are not shell-escaped or passed as arguments, a crafted username/password containing quotes, command substitution, shell metacharacters, path separators, or newlines can break out of the intended command and execute arbitrary commands as the SSH-connected account (and in several cases through `sudo`). This is particularly severe in `AddServerService`, where the command is explicitly modifying sudoers.

**Recommendation:**
Do not build privileged shell commands with string interpolation. Use a safer provisioning approach that avoids the shell entirely, or strictly validate allowed usernames/hostnames and escape every shell argument with a robust, centralized quoting routine. Also reject characters that are invalid for Linux usernames and never derive `/etc/sudoers.d` paths from unsanitized input.

## Finding 2 — Deterministic password encryption due to fixed zero IV

**Severity:** High

**Where:** `LinuxPass/Services/CryptorService.cs:14-16,35-37`

**Why this matters:**
The AES helper derives a key by truncating/padding the configured string and then always sets `aesAlg.IV = new byte[16]` for both encryption and decryption. Reusing a fixed all-zero IV makes encryption deterministic: the same plaintext under the same key always produces the same ciphertext.

For a password vault workflow, this leaks password equality across records and across time. An attacker who obtains the database can immediately tell which users share the same password or whether a password was rotated back to a previous value. Because the controller decrypts secrets on demand, compromise of the application key already exposes plaintexts; deterministic ciphertext adds extra leakage even before that point.

**Recommendation:**
Generate a fresh random IV for every encryption operation and store it alongside the ciphertext. Prefer an authenticated encryption construction such as AES-GCM (or encrypt-then-MAC) so tampering is also detected. Derive the encryption key from configuration using a binary secret of the correct size rather than `PadRight(...).Substring(...)` on a UTF-8 string.

## Finding 3 — Password is sent in the URL query string to the SMS provider

**Severity:** High

**Where:** `LinuxPass/Services/SendSMSService.cs:24-32`, `LinuxPass/Controllers/PasswordsController.cs:172-195`

**Why this matters:**
`SendSMSAsync` appends the decrypted password directly into the GET query string:

- `SMSMessage={encodedMessage}{decryptedPassword}`
- followed by `client.GetAsync(url)`

Sending secrets in the URL causes them to appear in multiple places outside the application’s control: reverse proxy logs, HTTP client diagnostics, browser/network tooling, intermediary monitoring systems, and potentially the SMS provider’s access logs. The password portion is not URL-encoded either, so special characters in generated passwords can also corrupt the request or change its semantics.

The controller decrypts the stored secret and immediately transmits it through this path, so every SMS operation leaks the plaintext password to URL-based logging surfaces.

**Recommendation:**
Do not transmit passwords in URL query strings. If SMS transmission is truly required, use the provider’s POST endpoint and place the message in the request body over HTTPS, encoding the full message payload. Prefer sending a one-time link or reset token instead of the actual password.

## Finding 4 — Raw exception details are returned to authenticated users from the password details endpoint

**Severity:** Medium

**Where:** `LinuxPass/Controllers/PasswordsController.cs:65-79`

**Why this matters:**
When decryption or another operation fails in `Details`, the catch block returns `Problem($"error: {ex}")`. Serializing the full exception object into the HTTP response can disclose stack traces, message text, type names, and potentially configuration-dependent details about crypto failures or data contents.

Even though the app requires authentication globally, every authenticated user can hit this endpoint. Detailed server-side exception data materially helps attackers understand key handling, storage format, and failure modes while also exposing internal implementation details that should stay in logs only.

**Recommendation:**
Return a generic user-safe error message from the controller and log the full exception server-side through the application logger. Apply the same pattern to other actions that currently return raw exception messages.
