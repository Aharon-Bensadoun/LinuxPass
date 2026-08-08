# Code Review Findings — 2026-08-08 (Run 5)

## Finding 1: Deterministic AES encryption leaks password equality across records
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Services/CryptorService.cs` derives the AES key by padding/truncating the configured key and always uses an all-zero IV:

```csharp
aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
aesAlg.IV = new byte[16]; // Initialization vector with zeros
```

The same helper is used whenever passwords are stored, for example in:
- `LinuxPass/Controllers/PasswordsController.cs:122`
- `LinuxPass/Services/ResetPassService.cs:41`

### Impact
Using a fixed IV makes encryption deterministic for identical plaintext under the same key. Anyone with database read access can identify when two stored credentials are equal, track password reuse over time, and weaken confidentiality guarantees expected from encrypted secrets.

### Recommendation
Use an authenticated encryption scheme with a fresh random nonce/IV per password (for example AES-GCM or AES-CBC + HMAC if legacy compatibility is required). Store the nonce alongside the ciphertext and derive the encryption key with a proper KDF instead of truncating/padding UTF-8 bytes.

---

## Finding 2: User-controlled values are interpolated directly into privileged SSH shell commands
- Severity: critical
- Confidence: high

### Evidence
The application builds shell commands with string interpolation and executes them remotely over SSH without quoting/escaping attacker-controlled values.

`LinuxPass/Services/AddUserService.cs`:
```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```

`LinuxPass/Services/AddServerService.cs`:
```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
```

The interpolated values originate from HTTP-bound model fields in controller actions:
- `LinuxPass/Controllers/PasswordsController.cs:96`
- `LinuxPass/Controllers/ServersController.cs:70`
- `LinuxPass/Controllers/ServersController.cs:130`

### Impact
A malicious operator can inject shell metacharacters via usernames or server-related fields and obtain arbitrary command execution on the remote host as the SSH-connected account, including through `sudo`. Because these commands modify local users and sudoers configuration, successful injection can directly result in full remote privilege escalation.

### Recommendation
Never compose shell commands by concatenating untrusted input. Strictly validate allowed usernames/hostnames against a tight whitelist and avoid the shell entirely where possible. If shell execution is unavoidable, pass arguments through a safe escaping routine designed for POSIX shells and remove unnecessary `sudo`/`NOPASSWD` behavior.

---

## Finding 3: Passwords are sent to the SMS gateway in the query string of a GET request
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Services/SendSMSService.cs` appends the decrypted password directly to the request URL and sends it with `HttpClient.GetAsync`:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

The password value is decrypted immediately before this call in `LinuxPass/Controllers/PasswordsController.cs:180-193`.

### Impact
Secrets placed in the URL commonly end up in reverse-proxy logs, web server logs, browser history, monitoring systems, and third-party gateway telemetry. This exposes the very credential the application is supposed to protect, even when transport encryption is enabled.

### Recommendation
Do not transmit passwords over SMS. If business requirements still mandate an SMS workflow, send a short-lived retrieval code or one-time reset token instead. At minimum, move sensitive fields into a POST body over TLS and ensure downstream providers do not log payloads.

---

## Validation
- `dotnet build LinuxPass.sln` ✅
  - Build succeeded.
  - Existing warnings observed: `NU1902` on `Microsoft.Identity.Web` 3.7.0 and nullable warnings in Razor views.
