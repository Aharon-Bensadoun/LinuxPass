# Review findings — 2026-08-08 (pass 6)

## 1. Remote command injection in SSH management services
- **Severity:** high
- **Files:** `LinuxPass/Services/AddUserService.cs`, `LinuxPass/Services/AddServerService.cs`, `LinuxPass/Services/ResetPassService.cs`

### Why this is a problem
Several SSH commands are assembled with string interpolation from values that ultimately come from the web application or remote host output:
- `AddUserService.AddUser`: `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `AddServerService.ResetPass`: `echo '{username} ALL=(ALL) NOPASSWD:ALL' ... /etc/sudoers.d/{username}`
- `ResetPassService.ResetPass`: `echo '{user}:{password}' | sudo chpasswd`

None of these values are shell-escaped. A username containing shell metacharacters, quotes, command substitution, or path separators can break out of the intended command and execute arbitrary commands as the SSH account, which is expected to have sudo privileges. In `ResetPassService`, the `user` values are read from the remote server and then injected back into another shell command without quoting discipline, so a hostile or malformed account name on the managed host can also trigger command execution.

### Risk / impact
This can lead to arbitrary command execution on managed Linux servers with elevated privileges, sudoers file corruption, or writing attacker-controlled content to privileged paths.

### Recommendation
Avoid building shell commands by concatenating untrusted values. Validate usernames against a strict allowlist (for example POSIX account naming rules), and either:
- use safe argument passing instead of shell pipelines, or
- apply robust shell escaping for every interpolated value and reject values that cannot be represented safely.

For sudoers management, never interpolate usernames directly into file paths or file contents without validation.

## 2. Stored passwords are encrypted with a static zero IV and no integrity protection
- **Severity:** high
- **File:** `LinuxPass/Services/CryptorService.cs`

### Why this is a problem
`CryptorService` derives the AES key by truncating/padding the configured string and always uses `new byte[16]` as the IV for both encryption and decryption.

That makes encryption deterministic: identical plaintexts under the same key produce identical ciphertexts. It also provides no authenticity/integrity protection, so ciphertext tampering is not detected before decryption. Because this application stores reversible credentials, these weaknesses directly affect the secrecy and integrity of all saved passwords.

### Risk / impact
An attacker who gains database access can correlate identical passwords across accounts and may tamper with ciphertexts without any authenticated-encryption check. The home-grown key derivation also weakens operational safety because small configuration mistakes silently produce a different raw AES key.

### Recommendation
Use an authenticated encryption scheme with a fresh random nonce/IV per record, such as AES-GCM, and store the nonce alongside the ciphertext. Derive keys with a standard KDF or load a properly sized binary key from configuration/secrets storage instead of padding/truncating a UTF-8 string.

## 3. Generated passwords are predictable because they use `System.Random`
- **Severity:** medium
- **File:** `LinuxPass/Services/PassGenService.cs`

### Why this is a problem
`PassGenService` uses a static `Random` instance to generate passwords. `System.Random` is not a cryptographically secure RNG and should not be used for credential generation.

This service is used when rotating server passwords and creating new user passwords, so generated credentials may be predictable to an attacker with knowledge of timing or internal state.

### Risk / impact
Predictable password generation lowers the effective entropy of issued credentials and can make newly created or rotated passwords guessable.

### Recommendation
Use `RandomNumberGenerator` / `RandomNumberGenerator.GetInt32` or another cryptographically secure RNG for all password generation.

## 4. Login endpoint disables account lockout on failed password attempts
- **Severity:** medium
- **File:** `LinuxPass/Areas/Identity/Pages/Account/Login.cshtml.cs`

### Why this is a problem
The login flow calls:

```csharp
await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false)
```

This explicitly disables ASP.NET Identity's lockout counter for password failures.

### Risk / impact
If no compensating controls are present at the edge, this makes online password guessing materially easier because repeated failed attempts do not trigger account lockout.

### Recommendation
Enable lockout on failure and configure appropriate lockout thresholds, or document/enforce an alternative brute-force mitigation such as strong rate limiting at the reverse proxy / identity provider.

## 5. State-changing password rotation is exposed as a GET action
- **Severity:** medium
- **Files:** `LinuxPass/Controllers/ServersController.cs`, `LinuxPass/Views/Servers/Index.cshtml`

### Why this is a problem
`ServersController.Rotate(int id)` performs a state-changing operation that resets passwords on remote hosts, but it is reachable through a normal `<a>` link and has no `[HttpPost]` or antiforgery protection.

Because it is a GET endpoint, browsers, crawlers, preloaders, or a cross-site request can trigger password rotation unintentionally.

### Risk / impact
This enables CSRF-style triggering of password resets and accidental execution by link prefetchers or administrators clicking crafted links.

### Recommendation
Require POST for rotation, add antiforgery validation, and invoke it from a form/button instead of a hyperlink. Consider adding an explicit confirmation step because the action is highly sensitive.

## 6. Application returns raw exception details to end users
- **Severity:** low
- **Files:** `LinuxPass/Controllers/PasswordsController.cs`, SSH/SMS services

### Why this is a problem
Several code paths return raw exception messages to the UI, for example:
- `PasswordsController.Details`: `return Problem($"error: {ex}");`
- SSH/SMS services return `ex.Message` strings, which controllers then place in `ViewData["Message"]`

These messages can expose stack traces, filesystem paths, hostnames, command errors, or provider-specific details to authenticated users.

### Risk / impact
Information disclosure makes further attacks easier and can reveal sensitive operational details about managed servers or application configuration.

### Recommendation
Log detailed exceptions server-side, but return generic user-facing error messages. Avoid surfacing raw command stderr or exception text in views.
