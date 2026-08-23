# Code review findings follow-up 10

## 1. Predictable password generation uses `System.Random`
- **Severity:** High
- **Location:** `LinuxPass/Services/PassGenService.cs:7-34`
- **Issue:** `GeneratePassword` uses a process-wide `System.Random` instance to generate credentials. `Random` is not a cryptographically secure PRNG, so generated passwords are predictable enough for an attacker who can observe outputs or approximate generator state.
- **Impact:** Newly created or rotated server passwords may be guessable, directly undermining the core security purpose of the application.
- **Recommendation:** Replace `System.Random` with `System.Security.Cryptography.RandomNumberGenerator` (or `RandomNumberGenerator.GetInt32`) and ensure generated passwords still satisfy the intended complexity requirements.

## 2. SSH command injection via unsanitized username/password/hostname interpolation
- **Severity:** Critical
- **Location:** `LinuxPass/Services/AddUserService.cs:22`, `LinuxPass/Services/AddServerService.cs:22-33`, `LinuxPass/Services/ResetPassService.cs:35-37`
- **Issue:** User-controlled and configuration-derived values are interpolated directly into shell commands executed remotely over SSH, for example:
  - `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  - `echo '{username} ALL=(ALL) NOPASSWD:ALL' ... /etc/sudoers.d/{username}`
  - `echo '{user}:{password}' | sudo chpasswd`
  None of these values are shell-escaped or validated against a strict allowlist.
- **Impact:** A crafted username such as one containing quotes, command separators, or path traversal characters can break out of the intended command and execute arbitrary shell commands as the SSH-connected privileged user on managed servers. This is full remote code execution on target infrastructure.
- **Recommendation:** Enforce strict server-side validation for usernames/hostnames against a conservative allowlist (for example POSIX-safe account names), avoid shell string concatenation, and pass data through safer mechanisms where possible. At minimum, correctly shell-escape every interpolated value and reject unsafe characters for filenames like `/etc/sudoers.d/{username}`.

## 3. `SendSMS` endpoint is missing anti-forgery protection
- **Severity:** High
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:171-196`, `LinuxPass/Views/Passwords/Details.cshtml:75-94`
- **Issue:** `SendSMS` is a state-changing POST action but lacks `[ValidateAntiForgeryToken]`. The corresponding form also does not emit an anti-forgery token explicitly.
- **Impact:** Any authenticated user visiting an attacker-controlled page can be tricked into submitting the form and sending decrypted passwords to arbitrary phone numbers chosen by the attacker, creating a practical credential exfiltration path.
- **Recommendation:** Add `[ValidateAntiForgeryToken]` to `SendSMS` and include the anti-forgery token in the form. Consider additional authorization checks and rate limiting because this action handles secret material.

## 4. SMS provider request leaks plaintext passwords in the URL query string
- **Severity:** Critical
- **Location:** `LinuxPass/Services/SendSMSService.cs:18-28`
- **Issue:** The SMS request appends `decryptedPassword` directly to the GET query string: `...?SMSMessage={encodedMessage}{decryptedPassword}&...`. Query strings are commonly logged by reverse proxies, application telemetry, browser/network tooling, and third-party providers.
- **Impact:** Plaintext credentials are exposed far beyond the intended recipient, potentially to infrastructure logs, monitoring systems, support staff, and any intermediary that records request URLs. Even with HTTPS, this is still a major secret-handling failure.
- **Recommendation:** Do not send secrets in query strings. Use a POST request with the secret in the request body if the provider supports it, minimize logging, and reconsider whether SMS is an acceptable transport for passwords at all.
