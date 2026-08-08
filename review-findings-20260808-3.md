# Code review findings — 2026-08-08 (pass 3)

## 1. Command injection in remote SSH command construction
- **Severity:** High
- **Files:** `LinuxPass/Services/AddUserService.cs:22`, `LinuxPass/Services/ResetPassService.cs:38`, `LinuxPass/Services/AddServerService.cs:22`, `LinuxPass/Services/AddServerService.cs:32`

### Why this is a problem
User-controlled and configuration-controlled values are interpolated directly into shell commands executed over SSH:
- `username` and `password` in `AddUserService.AddUser`
- enumerated `user` and generated `password` in `ResetPassService.ResetPass`
- `username` and `pubkey` in `AddServerService.ResetPass`

Even though some values originate from the app or remote host, they are still unescaped shell data. A single quote, command substitution, newline, or shell metacharacter can break out of the intended command and execute arbitrary commands as the SSH user, which is explicitly granted sudo access by this application.

### Evidence
```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```
```csharp
var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
```
```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
```
```csharp
var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && echo '{pubkey}' | cat >> ~/.ssh/test");
```

### Recommended fix
Avoid shell string interpolation for credentials and account names. At minimum:
- strictly validate usernames against a safe allowlist such as `^[a-z_][a-z0-9_-]*[$]?$`
- reject or escape single quotes, newlines, and shell metacharacters in any value passed to the shell
- write files and passwords through safer mechanisms rather than `echo '...' | ...`
- do not construct sudoers entries or authorized key files with unescaped string concatenation

## 2. Stored passwords use deterministic AES with a zero IV and no integrity protection
- **Severity:** High
- **File:** `LinuxPass/Services/CryptorService.cs:10`

### Why this is a problem
The application encrypts every password with:
- a key derived by padding/truncating a string
- a fixed all-zero IV
- no authentication tag or MAC

This makes encryption deterministic: the same plaintext under the same key always produces the same ciphertext. That leaks equality information between passwords and enables ciphertext tampering without detection. It also means the configured key material is not being handled as a proper binary secret.

### Evidence
```csharp
aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
aesAlg.IV = new byte[16]; // Initialization vector with zeros
```

### Recommended fix
Use modern authenticated encryption:
- AES-GCM or another AEAD mode
- a fresh random nonce/IV per encryption
- store nonce + ciphertext + tag together
- load a real binary key from secure configuration/secret storage instead of truncating/padding arbitrary text

## 3. Password disclosure over HTTP GET query string to the SMS provider
- **Severity:** High
- **File:** `LinuxPass/Services/SendSMSService.cs:22`

### Why this is a problem
The decrypted password is appended directly into the outbound GET URL sent to the SMS gateway. Query strings are commonly logged by application proxies, reverse proxies, network devices, browser tooling, and third-party providers. This turns every SMS send into plaintext credential exposure outside the application boundary.

### Evidence
```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

### Recommended fix
Do not send passwords over SMS. If business requirements force out-of-band delivery, use a one-time secret retrieval flow. At absolute minimum, switch to POST, place data in the request body, and ensure the downstream provider contract and logging policies prevent secret retention.

## 4. Server onboarding grants permanent passwordless sudo to remote accounts
- **Severity:** High
- **File:** `LinuxPass/Services/AddServerService.cs:22`

### Why this is a problem
When onboarding a server, the application modifies sudoers so the specified remote account receives `NOPASSWD:ALL`. If that account is later compromised, the attacker gets unrestricted root execution on the managed server. This materially expands blast radius and creates persistent privilege escalation from a web-driven workflow.

### Evidence
```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
```

### Recommended fix
Use a dedicated least-privileged automation account with narrowly scoped sudo rules for the exact commands required. Avoid `NOPASSWD:ALL` entirely.

## 5. Password records can be deleted locally without removing or disabling the remote account
- **Severity:** Medium
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:155`, `LinuxPass/Controllers/ServersController.cs:178`

### Why this is a problem
The delete actions remove database entries only. They do not disable the remote Linux account, rotate credentials, or revoke the added SSH/sudo access. Operators may believe access was removed because the record disappears from the UI, while the remote account remains active.

### Evidence
```csharp
var password = await _context.Passwords.FindAsync(id);
if (password != null)
{
    _context.Passwords.Remove(password);
}
```
```csharp
var server = await _context.Servers.FindAsync(id);
if (server != null)
{
    _context.Servers.Remove(server);
}
```

### Recommended fix
Either enforce remote deprovisioning as part of deletion or clearly rename these operations to indicate they only remove local records. Ideally, make local deletion contingent on successful remote cleanup.

## 6. Detailed exception objects are returned to end users
- **Severity:** Medium
- **File:** `LinuxPass/Controllers/PasswordsController.cs:79`

### Why this is a problem
The `Details` action returns the full exception string to the client. That can leak cryptographic failures, stack details, configuration mistakes, or sensitive operational context.

### Evidence
```csharp
catch (Exception ex)
{
    return Problem($"error: {ex}");
}
```

### Recommended fix
Log the exception server-side and return a generic error message to the user.
