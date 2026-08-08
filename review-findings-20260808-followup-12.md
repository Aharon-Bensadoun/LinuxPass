# Code Review Follow-up — 2026-08-08 (Pass 12)

This follow-up captures additional security findings identified during a fresh review pass. It intentionally avoids duplicating the prior follow-up report.

## 1. High — Any authenticated user can view every stored password in cleartext
- **Where:** `LinuxPass/Controllers/PasswordsController.cs:45-76`, `LinuxPass/Views/Passwords/Details.cshtml:53-64`
- **What happens:** the application applies a global `RequireAuthenticatedUser()` policy in `Program.cs`, but there is no finer-grained authorization on password records. Any authenticated Entra ID user can browse `Passwords/Index`, pick any record id, open `Passwords/Details/{id}`, and the controller decrypts the stored secret and returns it to the browser.
- **Why this matters:** this makes the app a plaintext password disclosure portal for all signed-in users, regardless of operational need. A compromised low-privilege account would immediately expose all managed Linux credentials.
- **Recommendation:** introduce record-level authorization and least-privilege roles/groups before returning decrypted credentials. At minimum, restrict password viewing and SMS sending to a small admin group and log every access.

## 2. High — Password rotation endpoint is a state-changing GET vulnerable to CSRF-triggered secret rotation
- **Where:** `LinuxPass/Controllers/ServersController.cs:186-207`
- **What happens:** `Rotate(int id)` performs password resets on the target host and writes new credentials to the database, but it is exposed as a GET action with no anti-forgery validation.
- **Why this matters:** an attacker can force a logged-in user’s browser to request `/Servers/Rotate/{id}` via an image tag or hidden navigation. That silently rotates passwords for an entire server, causing denial of service and replacing credentials without explicit operator intent.
- **Recommendation:** change the endpoint to POST only, add `[ValidateAntiForgeryToken]`, and require an explicit confirmation workflow for bulk rotations.

## 3. Medium — SMS password delivery leaks secrets in URL query strings
- **Where:** `LinuxPass/Services/SendSMSService.cs:14-33`
- **What happens:** the SMS provider request is built as a GET URL containing the full decrypted password in the `SMSMessage` query parameter.
- **Why this matters:** query strings are routinely logged by reverse proxies, application telemetry, browser tooling, and upstream providers. Even if TLS is used, the password is replicated into multiple log surfaces outside the application’s control.
- **Recommendation:** use a POST request with the secret in the request body if the provider supports it. If SMS transmission is unavoidable, avoid sending the full password and prefer an out-of-band one-time retrieval flow.

## 4. Medium — README and sample configuration encourage committing live secrets
- **Where:** `README.md:33-41`, `README.md:101-108`, `LinuxPass/appsettings.json:10-23`
- **What happens:** the setup instructions tell operators to place database credentials, the encryption key, Azure AD settings, SMS settings, and certificate passwords directly in `appsettings.json` and deployment scripts. The repository also includes concrete secret-shaped placeholders and an example certificate password in `deploy.sh` instructions.
- **Why this matters:** teams frequently copy these examples into tracked files, which leads to long-lived secret exposure in git history and forks. For an app that handles privileged credentials, this sharply raises operational risk.
- **Recommendation:** document secret storage via environment variables or an external secret manager, provide `appsettings.Template.json` with non-sensitive placeholders, and remove hard-coded password examples from deployment guidance.
