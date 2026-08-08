# Code Review Findings — 2026-08-08 (Run 4)

## Scope reviewed
- `LinuxPass/Controllers/PasswordsController.cs`
- `LinuxPass/Controllers/ServersController.cs`
- `LinuxPass/Services/AddUserService.cs`
- `LinuxPass/Services/AddServerService.cs`
- `LinuxPass/Services/ResetPassService.cs`
- `LinuxPass/Services/CryptorService.cs`
- `LinuxPass/Services/SendSMSService.cs`
- Related Razor views and configuration samples

## Findings

### 1. Password reset can be triggered with a GET request, enabling CSRF on a destructive action
**Severity:** High

**Where:** `LinuxPass/Controllers/ServersController.cs:190`

**Why it matters:**
`Rotate(int id)` changes passwords on a remote host and writes new credentials into the database, but it is exposed as a plain GET action and linked from `Views/Servers/Index.cshtml` via an `<a>` tag. Any authenticated user who loads an attacker-controlled page can be forced to request `/Servers/Rotate/{id}` automatically through an image, iframe, or redirect. Because authentication cookies are sent with same-site top-level navigations and many embedding scenarios, this allows silent password rotation without user intent.

**Evidence:**
- Controller action performs the reset directly without `[HttpPost]` or `[ValidateAntiForgeryToken]`.
- View invokes it using a normal link:
  ` <a asp-action="Rotate" asp-route-id="@item.Id" ...>Rotate</a>`

**Recommended fix:**
Convert the action to POST-only, require an anti-forgery token, and invoke it from a form/button rather than an anchor. Destructive operations that mutate remote systems should not be reachable via GET.

---

### 2. Shell commands interpolate untrusted usernames and passwords directly, allowing command injection on managed servers
**Severity:** High

**Where:**
- `LinuxPass/Services/AddUserService.cs:22`
- `LinuxPass/Services/AddServerService.cs:22`
- `LinuxPass/Services/ResetPassService.cs:35`

**Why it matters:**
SSH commands are built with string interpolation and embed user-controlled or externally sourced values directly inside shell command text. Examples include `username`, generated passwords, and public key contents. If a username contains shell metacharacters (`'`, `;`, `` ` ``, `$()`, spaces, newlines, etc.), the command executed on the target Linux host can be altered. A malicious operator with UI access could create a crafted username and obtain arbitrary command execution as the SSH account used by the application, which is especially dangerous because the commands run through `sudo`.

**Evidence:**
- `AddUserService`: `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `AddServerService`: `echo '{username} ALL=(ALL) NOPASSWD:ALL' ... /etc/sudoers.d/{username}` and `echo '{pubkey}' ...`
- `ResetPassService`: `echo '{user}:{password}' | sudo chpasswd`

There is no validation or escaping enforcing a safe Linux username character set before these values reach the shell.

**Recommended fix:**
Do not compose shell commands with raw interpolation. Strictly validate Linux usernames against a conservative allowlist (for example `^[a-z_][a-z0-9_-]{0,31}$`), avoid passing secrets via shell syntax when possible, and use safer command construction/escaping strategies or non-shell mechanisms.

---

### 3. Stored passwords use deterministic AES with a zero IV, so identical plaintexts encrypt to identical ciphertexts
**Severity:** Medium

**Where:** `LinuxPass/Services/CryptorService.cs:12-35`

**Why it matters:**
The encryption routine derives the AES key by truncating/padding the configured string and always sets `aesAlg.IV = new byte[16]`. This makes encryption deterministic: the same plaintext under the same key always produces the same ciphertext. Anyone with database access can spot password reuse immediately, and the scheme provides weaker confidentiality than standard randomized authenticated encryption. The implementation also lacks integrity protection, so ciphertext tampering is not detected cryptographically.

**Evidence:**
- `EncryptString` and `DecryptString` both hard-code an all-zero IV.
- No per-record random nonce/IV is generated or stored.
- No authentication tag / MAC is stored alongside the ciphertext.

**Recommended fix:**
Use a modern authenticated encryption scheme with a unique random nonce per secret (for example AES-GCM), store the nonce with the ciphertext, and derive the encryption key from configuration using a proper binary secret rather than padded UTF-8 text.

---

## Validation
- `dotnet build LinuxPass.sln` ✅
  - Build succeeds.
  - Existing warnings remain, including `NU1902` for `Microsoft.Identity.Web` 3.7.0 and nullable warnings in Razor views.
