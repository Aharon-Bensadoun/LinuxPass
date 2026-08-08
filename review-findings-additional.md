# Additional code review findings

This document captures additional findings discovered after the earlier review run. Severity reflects exploitability and operational impact.

## 1. Critical — Command injection in remote SSH commands

**Files:**
- `LinuxPass/Services/AddUserService.cs`
- `LinuxPass/Services/AddServerService.cs`
- `LinuxPass/Services/ResetPassService.cs`

User-controlled or configuration-derived values are interpolated directly into shell commands executed over SSH:

- `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `echo '{username} ALL=(ALL) NOPASSWD:ALL' | ... /etc/sudoers.d/{username}`
- `echo '{user}:{password}' | sudo chpasswd`
- public key content is injected into a shell command without robust escaping

Because `username`, `hostname`, and key material are not safely quoted/validated for shell use, a crafted value can break out of the intended command and execute arbitrary commands on the target host with elevated privileges.

**Impact:** remote code execution on managed servers, privilege escalation, corruption of sudoers configuration.

**Recommendation:**
- Strictly validate allowed usernames/hostnames against a conservative regex.
- Avoid shell composition for privileged operations when possible.
- If shell execution is unavoidable, use robust shell escaping for every interpolated value.
- Never write directly to `/etc/sudoers` through concatenated shell strings; use a safer provisioning approach and validate with `visudo -c`.

## 2. Critical — Password disclosure via UI and SMS endpoint

**Files:**
- `LinuxPass/Controllers/PasswordsController.cs`
- `LinuxPass/Views/Passwords/Details.cshtml`
- `LinuxPass/Services/SendSMSService.cs`

`PasswordsController.Details` decrypts the stored password and renders it to any authenticated user. The details view then exposes the cleartext password in the DOM (`value="@Model.DecryptedPassword"`) and supports copy-to-clipboard.

Additionally, `SendSMS` decrypts and sends the password over SMS, which is not a secure channel for credential delivery.

**Impact:** any authenticated user can retrieve plaintext credentials for any stored account; browser extensions, shoulder surfing, DOM inspection, logs, screenshots, and insecure SMS delivery can leak credentials.

**Recommendation:**
- Enforce authorization boundaries so only explicitly permitted operators can access a given server/account.
- Avoid displaying reusable passwords in plaintext; prefer rotation/reset flows and one-time reveal with audit logging if business-critical.
- Remove SMS-based password delivery or replace it with a more secure out-of-band approach.

## 3. High — Missing anti-forgery protection on password SMS action

**Files:**
- `LinuxPass/Controllers/PasswordsController.cs`
- `LinuxPass/Views/Passwords/Details.cshtml`

`PasswordsController.SendSMS` is `[HttpPost]` but does **not** use `[ValidateAntiForgeryToken]`. The corresponding form in `Details.cshtml` does not include an anti-forgery token.

Since all authenticated users appear to be broadly authorized, a malicious site could induce a logged-in operator to trigger SMS sending to an attacker-controlled number.

**Impact:** credential exfiltration through CSRF.

**Recommendation:** add `[ValidateAntiForgeryToken]` and include the anti-forgery token in the form. Consider making the action permission-restricted and audited.

## 4. High — State-changing rotate operation exposed as GET

**Files:**
- `LinuxPass/Controllers/ServersController.cs`
- `LinuxPass/Views/Servers/Index.cshtml`

`ServersController.Rotate(int id)` performs password rotation across server accounts but is reachable through a simple `<a>` link, i.e. a GET request.

GET requests must be safe and idempotent; using GET for password rotation enables accidental triggering by crawlers/prefetchers and CSRF-like abuse from external pages.

**Impact:** unintended mass password changes, service disruption, and loss of operator trust.

**Recommendation:** convert rotation to a POST-only action protected with anti-forgery and explicit confirmation.

## 5. High — Broken authorization model: any authenticated user can manage all servers and credentials

**Files:**
- `LinuxPass/Program.cs`
- controllers broadly

The app config adds a global `RequireAuthenticatedUser()` policy, but there is no evidence of role-based, policy-based, tenant-scoped, or record-level authorization. As a result, any authenticated user appears able to list servers, rotate passwords, create users, delete entries, decrypt credentials, and send SMS messages.

**Impact:** complete lateral access between operators and excessive privilege across the application.

**Recommendation:** define roles/policies (e.g. read-only, password-operator, server-admin), apply them to sensitive actions, and add per-server ownership/entitlement checks.

## 6. Medium — Sensitive data and internal errors returned directly to clients

**Files:**
- `LinuxPass/Controllers/PasswordsController.cs`

`Details` returns `Problem($"error: {ex}")`, which can disclose implementation details, stack content, connection details, or cryptographic failures to end users.

**Impact:** information disclosure that assists further attacks.

**Recommendation:** log the exception server-side and return a generic error message to the user.

## 7. Medium — Insecure SMS transport design leaks credentials in URL/query string

**Files:**
- `LinuxPass/Services/SendSMSService.cs`

The service sends the decrypted password via an HTTP GET request with query-string parameters:

`?SMSMessage=...{decryptedPassword}&SMSPhone=...`

Even if the upstream API uses HTTPS, query strings commonly leak through proxy logs, application logs, browser tooling, and monitoring systems. The message is also only partially URL-encoded: the template is encoded, but the password is concatenated afterward.

**Impact:** password leakage to intermediaries/logs and malformed requests for special characters.

**Recommendation:** do not transmit passwords via SMS. If the integration must remain, use POST with a request body, encode all user/content fields correctly, and avoid placing secrets in URLs.

## 8. Medium — Production hardening is incomplete

**Files:**
- `LinuxPass/Program.cs`
- `LinuxPass/appsettings.json`

`UseHsts()` is commented out in non-development environments. The SQL connection string template sets `TrustServerCertificate=True`, which can normalize insecure TLS validation if copied to production unchanged.

**Impact:** weaker transport security posture and increased risk of insecure deployments.

**Recommendation:** enable HSTS in production and document secure database TLS settings; avoid encouraging `TrustServerCertificate=True` for production configurations.

## 9. Medium — Server onboarding grants persistent passwordless sudo broadly

**Files:**
- `LinuxPass/Services/AddServerService.cs`

The onboarding logic appends:
- `{username} ALL=(ALL) NOPASSWD:ALL`
- `{username} ALL=(ALL:ALL) ALL`

This creates extremely broad privileges for the SSH user and may duplicate/conflict with sudoers entries. It also modifies sensitive files with ad-hoc shell commands.

**Impact:** privilege escalation, hard-to-audit server state, and risk of breaking sudo configuration.

**Recommendation:** minimize privileges, provision only the commands actually required, and manage sudoers entries through a hardened provisioning mechanism.

## 10. Low — Unused decrypted variable suggests unsafe debugging patterns

**Files:**
- `LinuxPass/Services/ResetPassService.cs`

The code decrypts a newly encrypted password into `decryptedPassword` and then does nothing with it. This is not directly exploitable, but it suggests plaintext password handling is happening more broadly than necessary.

**Recommendation:** remove unnecessary decryptions and minimize plaintext secret lifetime in memory.
