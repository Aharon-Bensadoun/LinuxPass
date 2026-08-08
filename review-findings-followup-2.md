# Code Review Findings Follow-up 2

## 1. OS command injection in SSH command construction
- **Severity:** high
- **Confidence:** high
- **Files:** `LinuxPass/Services/AddUserService.cs:22`, `LinuxPass/Services/AddServerService.cs:22`, `LinuxPass/Services/ResetPassService.cs:39`

### Why this is a problem
User-controlled or database-controlled values are interpolated directly into shell commands executed over SSH:
- `AddUserService` inserts `username` and `password` into `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `AddServerService` inserts `username` into multiple `sudo`/`visudo` commands
- `ResetPassService` inserts each discovered account name and generated password into `echo '{user}:{password}' | sudo chpasswd`

Because these commands are built as raw shell strings without strict validation or escaping, a crafted username containing shell metacharacters or quote characters can break out of the intended command and execute arbitrary shell syntax on the remote host. The `PasswordsController.Create` path accepts `password.Username` from a POST and passes it unchanged into `AddUserService.AddUser(...)`, so this is reachable from the web application.

### Impact
An authenticated user who can create a password/user entry can turn that request into arbitrary command execution on the managed Linux server under the SSH account used by the application. In practice that can become full host compromise because the commands already rely on `sudo`.

### Recommended fix
Avoid shell string concatenation for privileged operations. At minimum:
- strictly validate usernames against a safe allowlist such as `^[a-z_][a-z0-9_-]{0,31}$`
- reject any value containing quotes, whitespace, shell metacharacters, or path separators
- avoid piping credentials through shell syntax where possible
- centralize remote command execution behind helpers that perform safe argument encoding

## 2. Password rotation can be triggered via GET without anti-forgery protection
- **Severity:** medium
- **Confidence:** high
- **Files:** `LinuxPass/Controllers/ServersController.cs:208`

### Why this is a problem
`ServersController.Rotate(int id)` performs a state-changing operation: it connects to the target host, resets passwords for multiple accounts, and writes new encrypted passwords to the database. However, the action has no `[HttpPost]` constraint and no `[ValidateAntiForgeryToken]`, so it remains invokable by a simple GET request.

### Impact
Any authenticated user session can be tricked into triggering a full password rotation by visiting a page or loading an image/link pointing at `/Servers/Rotate/{id}`. This is a classic CSRF shape made worse by the fact that the action causes privileged remote changes and persistent database writes.

### Recommended fix
Make the action POST-only, require an anti-forgery token, and consider adding an explicit authorization policy for administrative operations.

## 3. Plaintext passwords are exposed in the UI and sent to an external SMS gateway over query strings
- **Severity:** high
- **Confidence:** high
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:67`, `LinuxPass/Controllers/PasswordsController.cs:180`, `LinuxPass/Views/Passwords/Details.cshtml:57`, `LinuxPass/Services/SendSMSService.cs:25`

### Why this is a problem
The application decrypts stored passwords and renders them directly in the password details page (`DecryptedPassword`). It also sends the plaintext password to the SMS provider by appending it to the request URL:
`{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone=...`

Sending secrets in a URL is particularly unsafe because URLs are commonly captured by reverse proxies, server access logs, browser history, debugging tools, and third-party monitoring. The view also normalizes operator access to plaintext credentials rather than limiting disclosure to narrowly controlled break-glass flows.

### Impact
Any compromise of HTTP logs, proxy logs, telemetry, or browser state can reveal end-user passwords. Internally, any authenticated user with access to the details page can recover plaintext passwords directly from the UI.

### Recommended fix
Do not transmit passwords over SMS or in query strings. If operational recovery is required, use one-time reset workflows or short-lived secrets delivered through a channel designed for secret transfer. In the application, minimize or remove plaintext password display and enforce tighter role-based access around any credential recovery feature.
