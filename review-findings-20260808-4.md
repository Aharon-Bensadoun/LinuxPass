# Code Review Findings — 2026-08-08 (Round 4)

This review documents additional findings that were not covered by the previous review round.

## 1. Command injection in remote SSH operations
- **Severity:** high
- **Where:** `LinuxPass/Services/AddUserService.cs:22`, `LinuxPass/Services/AddServerService.cs:22`, `LinuxPass/Services/AddServerService.cs:31`, `LinuxPass/Services/ResetPassService.cs:36`
- **What:** User-controlled or externally-sourced values are interpolated directly into shell commands executed over SSH.
- **Why it matters:** `username`, generated passwords, SSH public key content, and usernames enumerated from the target host are inserted into shell command strings without shell escaping. A crafted value containing quotes, command substitution, or shell metacharacters can break out of the intended command and execute arbitrary commands as the SSH account, which is explicitly granted sudo privileges by this application.
- **Evidence:**
  - `AddUserService` builds `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  - `AddServerService` builds sudoers and key-install commands with interpolated `{username}` and `{pubkey}`
  - `ResetPassService` builds `echo '{user}:{password}' | sudo chpasswd` for every discovered account
- **Recommended fix:** Avoid shell string interpolation for untrusted data. At minimum, strictly validate usernames against a conservative allowlist such as `^[a-z_][a-z0-9_-]{0,31}$`, and quote/escape every shell argument with a dedicated helper. Prefer command designs that pass data through standard input or use fixed scripts on the remote side instead of constructing compound shell expressions dynamically.

## 2. State-changing password rotation is exposed as a GET action without CSRF protection
- **Severity:** high
- **Where:** `LinuxPass/Controllers/ServersController.cs:180`, `LinuxPass/Views/Servers/Index.cshtml:65`
- **What:** Password rotation is triggered by a simple GET request via `<a asp-action="Rotate" ...>`.
- **Why it matters:** GET requests are expected to be safe and idempotent. Here, visiting a link performs a privileged state change across a remote server and the local password store. That enables cross-site request forgery and accidental activation by crawlers, link previewers, browser prefetching, or users clicking a shared URL.
- **Recommended fix:** Change `Rotate` to `[HttpPost]` with `[ValidateAntiForgeryToken]`, and submit it from a form button rather than an anchor tag. Consider adding an explicit confirmation step because the action rotates every eligible account on the host.

## 3. Raw server administrator passwords are persisted in the database during edits
- **Severity:** high
- **Where:** `LinuxPass/Controllers/ServersController.cs:112-143`, `LinuxPass/Models/Server.cs:10-13`, `README.md` SQL schema for `Servers`
- **What:** The edit flow binds `HostSrvPassword` and then calls `_context.Update(server)`, which persists the submitted administrator password into `Servers.HostSrvPassword`.
- **Why it matters:** The application appears to use the password only to bootstrap remote sudo/key configuration, but the edit action stores it at rest afterwards. That creates a high-value secret repository in the application database without any encryption, rotation, or retention controls. Anyone with read access to the database can recover reusable server administrator credentials.
- **Recommended fix:** Treat `HostSrvPassword` as an input-only field, not a persisted model property. Remove it from the entity stored in the database, or map it to a dedicated view model that is never written back. If a credential must be retained, store it in a dedicated secret manager rather than the application database.

## 4. Rotation can leave host passwords changed even when database writes fail mid-run
- **Severity:** medium
- **Where:** `LinuxPass/Services/ResetPassService.cs:31-53`
- **What:** The service changes each remote password first, then inserts the new encrypted password row and immediately saves. If a later database write fails, the server has already accepted some new passwords while the application has only a partial record of them.
- **Why it matters:** This creates operational lockout and inconsistent recovery data. For example, after rotating ten users, a transient database failure on user six leaves users one through six changed remotely, but only users one through five recorded locally.
- **Recommended fix:** Decouple remote execution from persistence and add failure handling. At minimum, collect all rotation results first, persist them in a single transaction, and abort/report clearly on any partial failure. A more robust design would update an existing current-secret record per account and preserve the prior known-good value until the new one is durably stored.
