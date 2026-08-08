# Code review findings — 2026-08-08 (follow-up 2)

## 1. Any authenticated user can read every stored password in cleartext
- **Severity:** high
- **Where:** `LinuxPass/Controllers/PasswordsController.cs:20`, `LinuxPass/Controllers/PasswordsController.cs:47`, `LinuxPass/Program.cs:14`

### Why this is a problem
The app applies only a global `RequireAuthenticatedUser()` policy in `Program.cs`, and `PasswordsController.Details(int? id)` decrypts and returns the selected password to the view for any authenticated user. There is no per-user authorization, ownership check, role check, or additional approval step before disclosing the secret.

As a result, any user who can sign in to the application can enumerate password IDs and retrieve the cleartext passwords for all managed Linux accounts across all servers.

### Impact
This defeats the purpose of storing the credentials encrypted at rest: after login, every authenticated user gets broad read access to every secret. In a shared enterprise tenant, compromise of any low-privilege application account becomes compromise of all managed server accounts.

### Recommendation
Restrict password viewing to a narrowly scoped admin role or an explicit secret-access permission, and enforce authorization in the controller before decrypting. Ideally also avoid rendering the secret directly in the page unless there is a just-in-time reveal flow with audit logging.

## 2. State-changing server password rotation is exposed as a GET action without CSRF protection
- **Severity:** high
- **Where:** `LinuxPass/Controllers/ServersController.cs:207`

### Why this is a problem
`ServersController.Rotate(int id)` performs a privileged state-changing operation: it connects over SSH and rotates passwords for accounts on the target server, then writes the new encrypted passwords into the database. However, the action is not decorated with `[HttpPost]` and does not use `[ValidateAntiForgeryToken]`.

Because it is callable as a GET, an attacker can trigger it with a simple cross-site request (for example via an `<img>` or auto-submitted link) against a victim who is already authenticated to the application.

### Impact
A CSRF attacker can force password rotation on managed servers, causing account lockouts, operational disruption, and unauthorized secret regeneration without the victim intentionally initiating the action.

### Recommendation
Make `Rotate` a POST-only action protected by anti-forgery validation. Update the UI to submit a form with an anti-forgery token, and consider requiring elevated authorization for rotation operations.

## 3. SSH commands are built by string interpolation with untrusted input, enabling remote command injection
- **Severity:** high
- **Where:** `LinuxPass/Services/AddUserService.cs:23`, `LinuxPass/Services/AddServerService.cs:22`, `LinuxPass/Services/AddServerService.cs:31`, `LinuxPass/Services/ResetPassService.cs:35`

### Why this is a problem
Several services interpolate user-controlled or externally sourced values directly into shell commands executed over SSH:
- `AddUserService` inserts `username` and generated `password` into `sudo useradd -m ... && echo 'user:pass' | sudo chpasswd`
- `AddServerService` inserts `username` into sudoers-related commands and inserts the configured public key into a shell `echo`
- `ResetPassService` inserts both enumerated usernames and generated passwords into `echo 'user:pass' | sudo chpasswd`

The input is not shell-escaped or validated against a strict allowlist. A crafted username or other unexpected value containing shell metacharacters or quotes can break out of the intended command and execute arbitrary commands on the managed server with the privileges granted to the SSH account.

### Impact
This can lead to full remote code execution on managed Linux servers, including privilege escalation if the SSH account has sudo access as assumed by the application workflow.

### Recommendation
Do not construct shell commands by concatenating raw values. Validate usernames against a strict POSIX-safe pattern, avoid `echo` pipelines for credential changes, and pass data through safer mechanisms such as dedicated scripts with positional arguments that are robustly escaped, or system APIs invoked by a controlled helper.
