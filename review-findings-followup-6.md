# Code review findings follow-up 6

## 1. CSRF protection missing on password-by-SMS endpoint
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:172`, `LinuxPass/Views/Passwords/Details.cshtml:77`
- **Issue:** `SendSMS` is a state-changing POST action that sends a credential out-of-band, but it is missing `[ValidateAntiForgeryToken]`. The corresponding form in `Details.cshtml` also does not render an anti-forgery token.
- **Impact:** Any site able to induce an authenticated browser to submit a cross-site POST can trigger SMS delivery of a stored password to an arbitrary phone number supplied in the forged request.
- **Recommendation:** Add `[ValidateAntiForgeryToken]` to `SendSMS` and include `@Html.AntiForgeryToken()` in the form.

## 2. Password is sent to the SMS gateway in the query string
- **Severity:** high
- **Location:** `LinuxPass/Services/SendSMSService.cs:24-31`
- **Issue:** `SendSMSAsync` appends the decrypted password directly into the URL query string of a GET request. Query strings are routinely logged by reverse proxies, app servers, browser/network tooling, and third-party providers.
- **Impact:** The very secret being protected can leak through logs and observability pipelines even when TLS is enabled, creating long-lived credential exposure outside the application database.
- **Recommendation:** Use a POST request with the secret in the request body, or avoid sending passwords by SMS entirely. At minimum, never place the password in the URL.

## 3. Shell command injection through unescaped SSH command arguments
- **Severity:** high
- **Location:** `LinuxPass/Services/AddUserService.cs:20`, `LinuxPass/Services/AddServerService.cs:20,30`, `LinuxPass/Services/ResetPassService.cs:37`
- **Issue:** User-controlled and externally sourced values such as `username`, generated `password`, and SSH public key contents are interpolated directly into shell commands executed via SSH. No quoting/escaping strategy is applied that would make these values safe for the remote shell.
- **Impact:** A crafted username, server-side account name, or key content containing shell metacharacters or quotes can break out of the intended command and execute arbitrary commands on the managed Linux servers with elevated privileges.
- **Recommendation:** Stop building shell commands with raw string interpolation. Use a robust shell-escaping routine for every argument, or better, upload scripts/files and pass validated arguments through a safer channel. Also validate usernames against a strict allowlist before use.

## 4. Server rotation is triggered through an unprotected GET endpoint
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/ServersController.cs:185`
- **Issue:** `Rotate(int id)` performs password rotation across a server but is exposed as a GET action with no anti-forgery protection.
- **Impact:** Crawlers, prefetchers, links, or cross-site image/script requests can trigger unintended password rotation for a server, causing operational disruption and unexpected credential changes.
- **Recommendation:** Restrict the action to POST only, add anti-forgery validation, and invoke it from an explicit form/button rather than a navigational GET.
