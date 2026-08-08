# Code review findings — 2026-08-08 (pass 5)

## 1. State-changing password rotation is exposed as a GET action without CSRF protection
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:208`, `LinuxPass/Views/Servers/Index.cshtml:57`

### Why this is a problem
`ServersController.Rotate(int id)` performs a privileged state-changing operation: it connects over SSH, rotates passwords for users on the target host, and persists the new encrypted passwords in the database. However, the action is exposed as a plain GET endpoint and is linked from the UI with a normal `<a>` element.

That means a malicious site can trigger password rotation in a victim's authenticated browser just by causing a navigation or loading the URL. Because the app applies a global authorization policy, the request will run with the victim's session if they are logged in.

### Impact
An attacker can force unexpected password rotations on managed servers, causing disruption, credential churn, and possible operational lockouts.

### Recommendation
Change `Rotate` to a POST-only action, require `[ValidateAntiForgeryToken]`, and invoke it from a form rather than a link.

---

## 2. SMS sending endpoint lacks anti-forgery validation
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:171`, `LinuxPass/Views/Passwords/Details.cshtml:77`

### Why this is a problem
`PasswordsController.SendSMS(...)` is a POST action that causes an external side effect, but it does not use `[ValidateAntiForgeryToken]`. The corresponding form in `Views/Passwords/Details.cshtml` also omits an anti-forgery token.

An attacker can therefore cause an authenticated user to submit a forged request that sends a password over SMS to an arbitrary number.

### Impact
This can be used to exfiltrate credentials to attacker-controlled phone numbers and to abuse the SMS gateway.

### Recommendation
Add `[ValidateAntiForgeryToken]` to the action and include `@Html.AntiForgeryToken()` in the form.

---

## 3. Password encryption uses a fixed zero IV, making ciphertext deterministic
- **Severity:** High
- **Location:** `LinuxPass/Services/CryptorService.cs:12-33`

### Why this is a problem
`CryptorService` derives the AES key directly from configuration text and sets `aesAlg.IV = new byte[16]` for every encryption. Reusing a constant IV makes encryption deterministic: identical plaintexts encrypted with the same key always produce identical ciphertexts.

For a password vault / credential management workflow, this leaks equality information across records and weakens confidentiality guarantees. It also deviates from standard authenticated-encryption practice.

### Impact
Observers with database access can detect when two stored passwords are equal and can perform correlation analysis across users and servers.

### Recommendation
Use a fresh random IV (or nonce) for every encryption and store it alongside the ciphertext. Prefer an authenticated encryption construction such as AES-GCM, or at least pair CBC/CTR with integrity protection.

---

## 4. Passwords are appended to the SMS provider URL query string
- **Severity:** High
- **Location:** `LinuxPass/Services/SendSMSService.cs:24-32`

### Why this is a problem
`SendSMSService` sends the decrypted password as part of the query string in a GET request:
- the password is concatenated into `url`
- then transmitted with `client.GetAsync(url)`

Secrets in query strings are commonly captured by reverse proxies, web server logs, monitoring systems, browser history, and third-party telemetry. Even if HTTPS is used, the plaintext password may still be exposed in multiple logging layers.

### Impact
Decrypted credentials can leak outside the application boundary through infrastructure logs and observability tooling.

### Recommendation
Do not transmit secrets in query parameters. Use a POST request with the secret in the request body if the provider supports it, and minimize or eliminate SMS-based password delivery entirely.

---

## 5. Exception details are returned directly to end users from password decryption flow
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:80`

### Why this is a problem
In `PasswordsController.Details`, failures during decryption are returned as:

```csharp
return Problem($"error: {ex}");
```

This exposes raw exception details to the client. Depending on the failure mode, that can reveal stack traces, configuration-related information, invalid ciphertext details, or library behavior that helps an attacker understand the system.

### Impact
Information disclosure that can aid targeted attacks and leak internal implementation details.

### Recommendation
Log the exception server-side and return a generic error message to the client.
