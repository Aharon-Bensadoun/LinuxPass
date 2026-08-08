# Review findings — 2026-08-08 (pass 5)

## 1. SSH command injection in server provisioning and password rotation services
**Severity:** high

**Where:**
- `LinuxPass/Services/AddServerService.cs:21`
- `LinuxPass/Services/AddUserService.cs:22`
- `LinuxPass/Services/ResetPassService.cs:37`

**Why this is a problem:**
These services build shell commands by interpolating attacker-controlled values directly into the command string executed over SSH:
- `username` is embedded in `useradd`, `chpasswd`, `visudo`, and `/etc/sudoers.d/{username}` paths.
- `password` is embedded in `echo '{username}:{password}' | sudo chpasswd`.
- `pubkey` is embedded in `echo '{pubkey}' | ...`.

The controller paths feeding these values (`ServersController.Create/Edit` and `PasswordsController.Create`) accept user-supplied form input and do not constrain it to a safe character set. A crafted username containing shell metacharacters or quotes can therefore break out of the intended command and execute arbitrary commands on the managed host with the application's SSH privileges.

**Proof from code:**
- `AddUserService.AddUser(...)` executes:
  - `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `AddServerService.ResetPass(...)` executes:
  - `echo '{username} ALL=(ALL) NOPASSWD:ALL' | ...`
  - `sudo tee /etc/sudoers.d/{username}`
- `ResetPassService.ResetPass(...)` executes:
  - `echo '{user}:{password}' | sudo chpasswd`

Because the code relies on remote shell parsing, values like `bob; touch /tmp/pwned #` or a single quote in the password/username are enough to alter the executed command stream.

**Impact:**
An authenticated user of the web app can turn normal server/user-management flows into arbitrary command execution on target Linux hosts, leading to full compromise of managed servers.

**Recommended fix:**
Avoid constructing shell commands with raw interpolation. Restrict usernames to a strict whitelist (for example POSIX-safe account names), avoid `echo ... | chpasswd` when values may contain quotes, and pass data through a safer channel (e.g. upload a script with validated arguments, or escape every shell argument correctly before invoking the remote shell).

## 2. Password rotation is a state-changing GET endpoint with no CSRF protection
**Severity:** high

**Where:**
- `LinuxPass/Controllers/ServersController.cs:184`
- `LinuxPass/Views/Servers/Index.cshtml:60`

**Why this is a problem:**
`ServersController.Rotate(int id)` performs a sensitive operation: it connects to the server, resets passwords for all eligible users, and stores the new credentials in the database. However, the action is exposed as a plain GET endpoint and is linked from the index page with a normal anchor tag.

Because GET requests do not carry anti-forgery validation here, any external site can cause a logged-in user’s browser to request `/Servers/Rotate/{id}` (for example via an `<img>` or auto-loading link). That makes forced password rotation CSRFable.

**Proof from code:**
- The action has no `[HttpPost]` or `[ValidateAntiForgeryToken]` attributes.
- The UI triggers it with `<a asp-action="Rotate" asp-route-id="@item.Id">`.
- The action calls `resetPassService.ResetPass(...)`, which changes passwords on the remote host and persists new password rows.

**Impact:**
An attacker can silently trigger disruptive credential rotation against managed servers whenever an authenticated operator visits an attacker-controlled page, causing account lockouts, operational disruption, and unauthorized password issuance into the application database.

**Recommended fix:**
Make `Rotate` a POST-only action protected by `[ValidateAntiForgeryToken]`, and invoke it from a form submission rather than a link. Consider adding an explicit authorization policy and confirmation step because this operation rotates all managed user passwords on a host.

## 3. Detailed exception disclosure leaks internals to authenticated users
**Severity:** medium

**Where:**
- `LinuxPass/Controllers/PasswordsController.cs:72`

**Why this is a problem:**
When password decryption fails in `PasswordsController.Details`, the controller returns `Problem($"error: {ex}")`. Interpolating the full exception object into the HTTP response discloses stack traces, exception types, and potentially sensitive configuration-dependent details to the caller.

Given this endpoint handles encrypted credentials, any decryption/configuration error can expose implementation details about the encryption path or environment to any authenticated user.

**Proof from code:**
```csharp
catch (Exception ex)
{
    return Problem($"error: {ex}");
}
```

**Impact:**
Attackers gain internal diagnostic details that make further exploitation easier and may reveal sensitive operational information during failures.

**Recommended fix:**
Return a generic user-facing error message and log the exception server-side instead. Do not include `ex.ToString()` or equivalent exception details in HTTP responses.
