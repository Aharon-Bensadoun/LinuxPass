# Code review findings — 2026-08-08 follow-up 8

## 1. State-changing password rotation is exposed as a GET endpoint without CSRF protection
- **Severity:** high
- **Files:** `LinuxPass/Controllers/ServersController.cs:208`, `LinuxPass/Views/Servers/Index.cshtml:70`

### Why this is a problem
`ServersController.Rotate(int id)` performs a sensitive state-changing operation: it connects to the remote server, rotates passwords for accounts, and writes the new encrypted passwords to the database. However, the action is exposed as a plain GET endpoint and the UI triggers it via an `<a>` link.

That means any authenticated browser session can be tricked into rotating passwords simply by visiting a page containing an image/link/script tag pointing to `/Servers/Rotate/{id}`. Because the endpoint is GET and has no anti-forgery validation, this is a textbook CSRF issue on a highly privileged action.

### Evidence
- Controller action has no `[HttpPost]` and no `[ValidateAntiForgeryToken]`.
- View renders it as:
  - `<a asp-action="Rotate" asp-route-id="@item.Id" ...>Rotate</a>`

### Recommended fix
Convert `Rotate` to a POST-only action with `[ValidateAntiForgeryToken]`, and replace the link in the view with a form submit button.

---

## 2. Remote shell command injection via unescaped username/password/public key interpolation
- **Severity:** high
- **Files:** `LinuxPass/Services/AddServerService.cs:24`, `LinuxPass/Services/AddServerService.cs:34`, `LinuxPass/Services/AddUserService.cs:25`, `LinuxPass/Services/ResetPassService.cs:39`

### Why this is a problem
Several SSH commands are constructed by interpolating untrusted or semi-trusted values directly into shell command strings:

- `AddServerService` interpolates `username` into sudoers modification commands and file paths.
- `AddServerService` interpolates `pubkey` into a single-quoted shell string.
- `AddUserService` interpolates `username` and `password` into `useradd` / `chpasswd` shell commands.
- `ResetPassService` interpolates `user` and generated `password` into `chpasswd`.

If any interpolated value contains shell metacharacters, quotes, command substitution syntax, newlines, or path separators, the remote shell can interpret that content as additional commands or altered arguments. Even values that are usually “internal” are not guaranteed to be shell-safe: usernames come from HTTP input in the create-user/server flows, and public keys routinely contain characters that break simplistic quoting if not encoded safely.

This can lead to arbitrary command execution on managed servers, malformed sudoers files, or privilege escalation beyond the intended operation.

### Evidence
Examples from the code:
- `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo`
- `echo '{pubkey}' | cat >> ~/.ssh/test`
- `echo '{user}:{password}' | sudo chpasswd`

### Recommended fix
Do not compose shell commands by direct string interpolation. At minimum:
- strictly validate usernames against a safe allowlist (for example POSIX username rules),
- avoid embedding secrets and public-key material directly in shell fragments,
- pass content through a safe transport/encoding strategy (for example base64 + decode remotely),
- and prefer command patterns that avoid shell parsing where possible.

---

## 3. Password reveal/send actions are available without any authorization checks
- **Severity:** high
- **Files:** `LinuxPass/Controllers/PasswordsController.cs`, `LinuxPass/Controllers/ServersController.cs`

### Why this is a problem
Neither controller has `[Authorize]`, and no individual action performs access-control checks. As written, any unauthenticated visitor who can reach the application can:

- list managed servers,
- trigger password rotation,
- create remote users,
- open password details pages,
- decrypt stored passwords server-side,
- and send those passwords out over SMS.

This is a complete privilege-boundary failure for an app whose core purpose is credential management.

### Evidence
- No `Authorize` attribute found in `LinuxPass/Controllers`.
- `PasswordsController.Details` decrypts and returns plaintext passwords.
- `PasswordsController.SendSMS` decrypts the stored password and sends it externally.
- `ServersController.Rotate` performs privileged remote actions.

### Recommended fix
Require authenticated/authorized access at the controller or application level immediately, then restrict sensitive actions to the narrowest appropriate role/policy.
