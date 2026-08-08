# Code Review Findings — Follow-up 7

## 1. Password rotation is triggered via GET, enabling CSRF and accidental execution
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:208`, `LinuxPass/Views/Servers/Index.cshtml:70`

### Why this matters
`ServersController.Rotate(int id)` performs a state-changing operation: it connects to a server, rotates passwords for multiple accounts, and persists the new encrypted passwords in the database. However, the action is exposed as a plain GET endpoint and is linked from the UI with a normal `<a>` tag.

That means the rotation can be triggered by:
- a malicious page embedding the URL,
- browser prefetching/crawling,
- users opening links in new tabs by mistake,
- automated scanners following internal links.

Because the app applies a global authenticated-user policy, any signed-in user who can load the page can also be induced to fire the GET request. For a privileged operational action like password rotation, this is a classic CSRF footgun.

### Recommended fix
Convert `Rotate` into a POST-only action protected with `[ValidateAntiForgeryToken]`, and replace the anchor in `Views/Servers/Index.cshtml` with a form containing a submit button.

---

## 2. Remote command injection risk from unsanitized SSH command construction
- **Severity:** Critical
- **Location:** `LinuxPass/Services/AddUserService.cs:22`, `LinuxPass/Services/AddServerService.cs:22`, `LinuxPass/Services/AddServerService.cs:31`

### Why this matters
Several services build shell commands by interpolating untrusted or weakly validated values directly into strings executed over SSH:

- `AddUserService`:
  - `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `AddServerService`:
  - `echo '{username} ALL=(ALL) NOPASSWD:ALL' ... /etc/sudoers.d/{username}`
  - `echo '{pubkey}' | cat >> ~/.ssh/test`

`username` comes from form input (`Passwords/Create`, `Servers/Create`, `Servers/Edit`) and is not validated against a safe character allowlist before being embedded into shell commands. Even if some inputs are usually benign, a crafted value containing shell metacharacters, quotes, command substitution, or path separators can alter the executed command on the remote host.

This is especially dangerous here because the commands invoke `sudo`, create accounts, and modify sudoers configuration. The impact is remote code execution on managed Linux servers.

### Recommended fix
- Enforce strict server-side validation on usernames/hostnames (for example `^[a-z_][a-z0-9_-]{0,31}$` for Linux usernames, adjusted as needed).
- Never compose shell commands with raw interpolation for privileged operations.
- Prefer passing arguments through a hardened script or API on the target host.
- At minimum, apply robust shell escaping for every interpolated value, including usernames, passwords, and key material.

---

## 3. SMS form posts without anti-forgery protection while sending secrets out-of-band
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:164`, `LinuxPass/Views/Passwords/Details.cshtml:69`

### Why this matters
`PasswordsController.SendSMS` is a POST action that decrypts a stored password and sends it to a phone number supplied by the request. Unlike the other POST handlers in the project, it is not decorated with `[ValidateAntiForgeryToken]`, and the corresponding form does not emit an anti-forgery token.

An attacker cannot read the response because of same-origin policy, but they do not need to: a forged POST is enough to cause the application to transmit the decrypted credential to an attacker-controlled phone number, provided the victim is authenticated.

### Recommended fix
Add `[ValidateAntiForgeryToken]` to `SendSMS` and include the Razor anti-forgery token in the form. Given the sensitivity of the action, consider an additional confirmation step or tighter authorization policy as well.
