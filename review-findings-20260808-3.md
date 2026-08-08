# Code Review Findings — 2026-08-08 (pass 3)

## Finding 1 — Remote command injection through unsanitized SSH command construction
**Severity:** high

**Where:**
- `LinuxPass/Services/AddUserService.cs:23`
- `LinuxPass/Services/AddServerService.cs:23,32`
- `LinuxPass/Services/ResetPassService.cs:37`

**Why this is a problem:**
These services build shell commands with string interpolation and embed attacker-controlled values directly into the command text sent over SSH.

Examples:
- `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `echo '{username} ALL=(ALL) NOPASSWD:ALL' ... /etc/sudoers.d/{username}`
- `echo '{user}:{password}' | sudo chpasswd`

`username`, `hostname`-related selections, and especially generated or persisted user names are not shell-escaped. A malicious operator can submit a crafted username such as `bob; curl ...` or include quotes/newlines so that the remote shell executes arbitrary commands as the SSH account, which is expected to have sudo privileges. Because this application is explicitly a privileged password-management tool, this becomes authenticated RCE on managed servers.

**Evidence:**
`PasswordsController.Create` accepts `password.Username` from the request and passes it unchanged to `AddUserService.AddUser`. `ResetPassService` also interpolates enumerated remote usernames back into a shell command without escaping. No validation restricts usernames to a safe character set before command construction.

**Recommended fix:**
Avoid shell string concatenation for privileged operations. At minimum, validate usernames against a strict allowlist such as `^[a-z_][a-z0-9_-]*$` and use safe argument escaping for every shell value. Prefer invoking fixed commands with safely encoded inputs rather than building compound shell pipelines.

## Finding 2 — Password rotation is a state-changing GET endpoint with no CSRF protection
**Severity:** high

**Where:**
- `LinuxPass/Controllers/ServersController.cs:188`
- `LinuxPass/Views/Servers/Index.cshtml:58`

**Why this is a problem:**
`ServersController.Rotate(int id)` performs a destructive state-changing action: it connects to the target server, rotates every managed user password, and writes the new encrypted credentials to the database. However, the action is exposed as a plain GET endpoint and is linked from the UI with an `<a>` tag.

Because the application uses cookie-based authentication (`AddDefaultIdentity`), any authenticated user visiting an attacker-controlled page can be induced to trigger `/Servers/Rotate/{id}` via a simple cross-site image/link request. No anti-forgery token or POST requirement blocks the request.

**Impact:**
An attacker can force password rotations on arbitrary managed servers without the victim intentionally performing the action, causing operational disruption and credential churn.

**Recommended fix:**
Make rotation a POST-only action with `[HttpPost]` and `[ValidateAntiForgeryToken]`, and replace the link with a form submit button. Consider adding an explicit confirmation step and authorization policy if only a subset of users should be allowed to rotate credentials.

## Finding 3 — Raw exception details are returned to end users
**Severity:** medium

**Where:**
- `LinuxPass/Controllers/PasswordsController.cs:71`

**Why this is a problem:**
When password decryption fails in `PasswordsController.Details`, the catch block returns:

```csharp
return Problem($"error: {ex}");
```

This serializes the full exception text into the HTTP response. In production, decryption/configuration failures commonly include stack traces, type names, and sensitive operational details such as missing configuration keys, file paths, or cryptographic errors. That leaks internals to any authenticated user who can trigger the code path.

**Recommended fix:**
Log the exception server-side and return a generic user-facing error message. Avoid returning raw exception objects or stack traces in HTTP responses.
