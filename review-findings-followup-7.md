# Code review findings follow-up 7

## Finding 1 — Passwords are encrypted deterministically with a fixed zero IV
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Services/CryptorService.cs` derives the AES key by padding/truncating a configuration string and then always uses an all-zero IV for both encryption and decryption:

```csharp
aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
aesAlg.IV = new byte[16]; // Initialization vector with zeros
```

Because the IV never changes, encrypting the same plaintext with the same key always produces the same ciphertext. In this application, generated and rotated passwords are stored in `Passwords.EncryptedPassword`, so deterministic encryption leaks when two stored passwords are identical and removes an important security property expected from AES-CBC-style usage.

### Why this matters
A database reader who cannot decrypt values can still correlate equal passwords across users/servers and over time. This is especially problematic for a password vault/rotation tool, where stored secrets should not reveal equality patterns.

### Recommendation
Generate a fresh random IV for every encryption operation, store it alongside the ciphertext, and authenticate the ciphertext (for example by using AES-GCM or by storing an HMAC over IV+ciphertext).

## Finding 2 — SMS password delivery leaks the secret in the query string of an outbound GET request
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Services/SendSMSService.cs` builds a URL that includes the decrypted password directly in the query string and sends it with `HttpClient.GetAsync`:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

`PasswordsController.SendSMS` decrypts the stored password and passes it into this method:

```csharp
decryptedPassword = CryptorService.Cryptor.DecryptString(password.EncryptedPassword, _configuration["EncryptionKey"] ?? "");
string result = await sendSMSService.SendSMSAsync(smsPhone, decryptedPassword);
```

### Why this matters
Query strings are commonly logged by proxies, reverse proxies, monitoring systems, web servers, and third-party SMS providers. This design exposes account passwords well beyond the application boundary and makes accidental logging very likely.

### Recommendation
Do not transmit passwords through SMS. If a notification must be sent, prefer a one-time reset flow or a short-lived retrieval link. At minimum, use a POST request body over TLS and ensure the secret is never included in URLs or logs.

## Finding 3 — State-changing password rotation is exposed as a GET action without anti-forgery protection
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Controllers/ServersController.cs` exposes `Rotate(int id)` as a plain action with no `[HttpPost]` or `[ValidateAntiForgeryToken]` attributes:

```csharp
public async Task<IActionResult> Rotate(int id)
{
    var server = await _context.Servers.FindAsync(id);
    ...
    string result = await resetPassService.ResetPass(server.HostSrvName, server.HostSrvUsername, sshKey);
```

The method performs a state-changing operation: it connects to the target host, rotates passwords for multiple users, and inserts new `Password` rows via `ResetPassService.ResetPass`.

### Why this matters
A GET endpoint that changes server state is vulnerable to CSRF and accidental triggering by crawlers, prefetchers, or embedded links/images. A user merely visiting a page controlled by an attacker could trigger a password rotation against managed servers.

### Recommendation
Restrict this endpoint to POST only, require anti-forgery validation, and consider an explicit confirmation workflow for such a destructive action.

## Finding 4 — User-controlled values are interpolated directly into remote shell commands
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Services/AddUserService.cs` interpolates `username` and `password` directly into a shell command sent over SSH:

```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```

`LinuxPass/Services/ResetPassService.cs` similarly interpolates discovered usernames and generated passwords into a shell command:

```csharp
var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
```

These values are not shell-escaped before being embedded in the command string.

### Why this matters
If a username contains shell metacharacters or quoting characters, the command sent to the remote server can be altered. In `AddUserService`, `password.Username` comes from the MVC request model, so a malicious authenticated operator could inject arbitrary shell syntax into a command executed with sudo on the target host.

### Recommendation
Avoid shell interpolation for credentials and account names. Validate usernames against a strict allowlist (for example Linux username rules), and use safe argument passing/escaping or a non-shell mechanism for account management.
