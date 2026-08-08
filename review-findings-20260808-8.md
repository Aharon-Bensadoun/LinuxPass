# Security review findings — follow-up 8

## Confirmed findings

### 1. CSRF on password exfiltration via SMS endpoint
- **Severity:** High
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:172`, `LinuxPass/Views/Passwords/Details.cshtml:80`
- **Issue:** `PasswordsController.SendSMS` is a state-changing POST endpoint that decrypts a stored password and sends it to an attacker-controlled phone number, but it is missing `[ValidateAntiForgeryToken]`. The corresponding form in `Details.cshtml` also does not emit an antiforgery token explicitly. Because the app applies a global authenticated-user policy, a malicious site can cause a logged-in victim browser to submit a forged POST to `/Passwords/SendSMS` and trigger password delivery to an arbitrary number.
- **Impact:** Any authenticated session can be abused cross-site to exfiltrate stored credentials without the victim's intent.
- **Recommendation:** Require antiforgery validation on `SendSMS`, include an antiforgery token in the form, and consider an additional re-authentication or step-up confirmation before any plaintext secret delivery action.

### 2. Sensitive operation exposed over GET, enabling CSRF-triggered password rotation
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:208`, `LinuxPass/Views/Servers/Index.cshtml:65`
- **Issue:** `ServersController.Rotate` performs a password rotation action but is exposed as a GET endpoint and linked directly from the index page. Since GET requests are intended to be safe/idempotent and browsers can trigger them cross-site, an attacker can force an authenticated user to rotate server passwords simply by embedding the URL.
- **Impact:** Cross-site requests can trigger operationally disruptive password resets on managed servers, potentially causing outages, loss of access, or desynchronization with dependent systems.
- **Recommendation:** Change rotation to POST-only, protect it with antiforgery validation, and require an explicit confirmation workflow for this destructive administrative action.

### 3. Exception details returned directly to end users
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:80`
- **Issue:** The `Details` action catches exceptions and returns `Problem($"error: {ex}")`, which exposes the full exception object to the client. In ASP.NET this can include internal messages, stack-trace-adjacent details, cryptographic failures, configuration mistakes, or data access information useful to an attacker.
- **Impact:** Attackers can harvest implementation details that reduce the effort needed for follow-on attacks or reconnaissance.
- **Recommendation:** Log the exception server-side and return only a generic error message to clients.

### 4. HSTS disabled in production pipeline
- **Severity:** Medium
- **Location:** `LinuxPass/Program.cs:32`
- **Issue:** In the production branch of the pipeline, `app.UseHsts()` is commented out. Even though `UseHttpsRedirection()` is enabled, lack of HSTS leaves first-visit and downgrade scenarios unprotected.
- **Impact:** Users can be exposed to SSL stripping or downgrade attacks in hostile network environments until HTTPS is established and trusted.
- **Recommendation:** Re-enable HSTS in production with an appropriate max-age and rollout plan.
