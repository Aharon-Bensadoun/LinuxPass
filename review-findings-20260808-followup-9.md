# Code Review Findings

## High severity

1. **Sensitive controllers are missing authorization guards**
   - `LinuxPass/Controllers/ServersController.cs:9`
   - `LinuxPass/Controllers/PasswordsController.cs:10`
   - `LinuxPass/Controllers/HomeController.cs:7`
   - The README says the app uses Entra ID authentication, but the MVC controllers that expose server inventory, decrypted passwords, password rotation, user creation, deletion, and SMS sending do not use `[Authorize]` at either controller or action scope.
   - In an ASP.NET Core app, relying only on UI navigation or assumed global config is fragile. If fallback authorization is not enforced in startup, these endpoints are reachable anonymously, including `Passwords/Details`, which decrypts and renders stored credentials.
   - **Impact:** unauthenticated users could enumerate infrastructure metadata, reveal plaintext credentials, trigger password rotation, create Linux users, delete records, and exfiltrate passwords over SMS.
   - **Recommendation:** require authenticated access by default with `[Authorize]` on the relevant controllers and keep any intentionally public routes explicitly marked with `[AllowAnonymous]`. Also verify that startup config enforces a fallback authorization policy.

2. **Password rotation is exposed as a GET action without CSRF protection**
   - `LinuxPass/Controllers/ServersController.cs:202`
   - `LinuxPass/Views/Servers/Index.cshtml:59`
   - `Rotate(int id)` performs a state-changing operation: it connects over SSH, resets passwords for users, and writes new encrypted passwords to the database. Despite that, it is implemented as a GET action and is linked via a normal `<a>` element.
   - GET requests must be safe and idempotent. As written, any embedded image/link or cross-site navigation can trigger password rotation for an authenticated operator.
   - **Impact:** CSRF and accidental activation can force password resets across a managed server, causing credential churn and potential service disruption.
   - **Recommendation:** change rotation to POST only, add `[ValidateAntiForgeryToken]`, and submit it from a form button rather than a hyperlink.

3. **SSH commands interpolate untrusted input directly into shell commands**
   - `LinuxPass/Services/AddServerService.cs:22`
   - `LinuxPass/Services/AddServerService.cs:32`
   - `LinuxPass/Services/AddUserService.cs:22`
   - `LinuxPass/Services/ResetPassService.cs:36`
   - Hostnames, usernames, generated passwords, and even public-key content are inserted directly into shell command strings executed remotely over SSH. There is no escaping/quoting strategy that safely handles shell metacharacters, quotes, command substitution, or newlines.
   - Example: `useradd -m {username}` and `echo '{username}:{password}' | sudo chpasswd` allow crafted values to break out of the intended command context.
   - **Impact:** an attacker who can influence these values can execute arbitrary commands on managed Linux hosts with the privileges of the SSH account, which appears to have sudo capabilities.
   - **Recommendation:** stop building shell commands with string interpolation. Use strict allowlists for usernames/hostnames, pass data via stdin or temporary files, and invoke safer command patterns that avoid shell parsing wherever possible.

## Medium severity

4. **SMS sending endpoint lacks anti-forgery protection and leaks the password in the query string to a third-party API**
   - `LinuxPass/Controllers/PasswordsController.cs:168`
   - `LinuxPass/Services/SendSMSService.cs:22`
   - `LinuxPass/Views/Passwords/Details.cshtml:75`
   - `SendSMS` is a POST action but is missing `[ValidateAntiForgeryToken]`, so it can be triggered cross-site for any authenticated user viewing the details page. The service then concatenates the decrypted password into the outbound GET URL.
   - Query strings are routinely logged by reverse proxies, application telemetry, browser/network tooling, and the SMS provider, so this design spreads plaintext credentials well beyond the application boundary.
   - **Impact:** attackers can induce credential exfiltration by SMS, and plaintext passwords may be retained in logs outside your control.
   - **Recommendation:** add anti-forgery validation and avoid transmitting secrets in a GET query string. Prefer a POST body to the provider, or reconsider whether sending reusable credentials over SMS is acceptable at all.

5. **Decrypted passwords are rendered back to the client on demand**
   - `LinuxPass/Controllers/PasswordsController.cs:58`
   - `LinuxPass/Views/Passwords/Details.cshtml:50`
   - The application decrypts stored passwords server-side and returns them to the browser in the page model, where they can be revealed and copied with client-side JavaScript.
   - Even if this is intentional for operators, it significantly enlarges the exposure surface: browser memory, clipboard history, screenshots, extensions, caches, and support tooling can all capture the secret.
   - **Impact:** compromise of an operator workstation or browser session directly exposes the managed Linux credentials.
   - **Recommendation:** minimize plaintext exposure, use one-time reveal flows with stronger authorization/auditing, and prefer server-side reset workflows over persistent password disclosure.
