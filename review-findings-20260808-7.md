# Security review findings — 2026-08-08 (round 3)

This report captures additional findings confirmed during follow-up review beyond the issues already documented in `review-findings-20260808-6.md`.

## 1. Stored credentials are disclosed to any authenticated user without object-level authorization
- **Severity:** High
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:49-80`, `LinuxPass/Views/Passwords/Details.cshtml`
- **Issue:** The app applies a global `RequireAuthenticatedUser()` policy in `Program.cs`, but there is no finer-grained authorization on password records. Any authenticated Entra ID user can request `Passwords/Details/{id}`, the controller decrypts `EncryptedPassword`, and the view renders the cleartext password with copy/SMS actions.
- **Impact:** Any authenticated account in the tenant can enumerate IDs and retrieve credentials for servers and Unix users they should not manage, resulting in full credential disclosure and likely downstream infrastructure compromise.
- **Evidence:** `Details(int? id)` loads the record only by primary key, decrypts it with the application-wide `EncryptionKey`, and returns `DecryptedPassword` to the view. There is no ownership, role, group, or per-server access check before disclosing the secret.
- **Recommendation:** Introduce authorization boundaries for secret access (for example per-server RBAC, Entra group checks, or explicit ownership). Treat password reveal and SMS export as privileged operations with explicit policy checks and auditing.

## 2. Server onboarding grants permanent passwordless sudo to the supplied SSH account
- **Severity:** Critical
- **Location:** `LinuxPass/Services/AddServerService.cs:24`
- **Issue:** Adding a server executes a remote command that appends `'{username} ALL=(ALL) NOPASSWD:ALL'` to sudoers and also writes a per-user sudoers file. This silently escalates the provided SSH account to unrestricted root-equivalent access on the managed host.
- **Impact:** Compromise of the app, its SSH key, or any authenticated user able to trigger management actions yields immediate root-level control of every onboarded server. This also weakens host hardening by permanently expanding privileged access beyond least privilege.
- **Evidence:** `AddServerService.ResetPass()` runs `sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo ...`.
- **Recommendation:** Do not grant blanket `NOPASSWD:ALL`. Use a dedicated service account provisioned out-of-band with the minimum commands required, or constrain sudoers entries to a tightly scoped command allowlist.

## 3. Sensitive exception details are returned to end users
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:78-80`, `LinuxPass/Controllers/PasswordsController.cs:164-169`
- **Issue:** Error handling returns raw exception content through `Problem($"error: {ex}")` and other detailed failure strings. These exceptions can contain stack traces, crypto failures, SQL details, remote hostnames, SSH errors, or configuration-dependent paths.
- **Impact:** An attacker can use malformed requests or trigger backend failures to harvest internal implementation details that help with lateral movement, credential attacks, and targeted exploitation.
- **Evidence:** `Details()` catches `Exception ex` and returns the exception object in the HTTP response. `SendSMS()` and the SSH service methods also bubble raw exception text back into user-visible messages.
- **Recommendation:** Log detailed exceptions server-side only, return generic user-facing errors, and normalize sensitive backend failures to opaque messages/codes.
