# Code Review Findings — Follow-up 15

## Scope
Review of the current `master` branch of `Aharon-Bensadoun/LinuxPass` as checked out in this workspace on 2026-08-08.

## Findings

### 1. Remote shell command injection in SSH administration flows
- **Severity:** high
- **Files:** `LinuxPass/Services/AddUserService.cs:25`, `LinuxPass/Services/AddServerService.cs:24`, `LinuxPass/Services/AddServerService.cs:34`, `LinuxPass/Services/ResetPassService.cs:39`

#### Why this matters
These services build shell commands by interpolating attacker-controlled or otherwise variable values directly into command strings executed over SSH. Examples include `username`, generated passwords, and the contents of the configured public key file.

Representative snippets:
- `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `echo '{username} ALL=(ALL) NOPASSWD:ALL' | ...`
- `echo '{pubkey}' | cat >> ~/.ssh/test`
- `echo '{user}:{password}' | sudo chpasswd`

Because no shell escaping or argument-safe transport is used, a crafted username such as `bob; rm -rf / #` or a value containing a single quote can break out of the intended command and execute arbitrary shell code on the managed server. The same problem applies to any generated password or public key containing `'`, which can also make legitimate operations fail unpredictably.

#### Recommendation
Do not compose shell commands by string interpolation. At minimum, strictly validate remote usernames against a safe allowlist (for example `^[a-z_][a-z0-9_-]*$`) and shell-escape every interpolated value. Prefer safer patterns such as:
- invoking remote commands with fixed command text and passing data through stdin,
- uploading files instead of `echo`-ing file contents into the shell,
- or using APIs/libraries that avoid a shell entirely.

---

### 2. SMS sending endpoint exfiltrates plaintext passwords in URL query strings
- **Severity:** high
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:172-194`, `LinuxPass/Services/SendSMSService.cs:25-32`

#### Why this matters
The `SendSMS` action decrypts the stored password and forwards it to `SendSMSService`. That service appends the plaintext password directly into a GET query string:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

Sending secrets in a URL is unsafe because URLs are commonly recorded by reverse proxies, web server access logs, APM tooling, browser/network debugging tools, and third-party gateway logs. This means every SMS request can leak the decrypted password far beyond the application boundary. In addition, only the static message prefix is URL-encoded; the password and other parameters are concatenated raw, so special characters in the password can corrupt the request or alter parameter parsing.

#### Recommendation
Do not transmit passwords in query strings. Use a POST request with the secret in the request body, and URL-encode or serialize all user-controlled fields correctly. Prefer sending one-time reset links or codes instead of redistributing the actual account password.

---

### 3. Password rotation can silently desynchronize the database from the real server state
- **Severity:** medium
- **Files:** `LinuxPass/Services/ResetPassService.cs:39-55`

#### Why this matters
During rotation, the code executes `sudo chpasswd` and immediately persists a new encrypted password record without checking whether the remote command succeeded:

```csharp
var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
...
var resetpassresult = command.Execute();
...
_context.Add(newpassword);
await _context.SaveChangesAsync();
```

Unlike `AddUserService` and `AddServerService`, this path never checks `command.ExitStatus` or `command.Error`. If `chpasswd` fails for one user (sudo policy issue, shell quoting breakage, expired privileges, locked account, etc.), the application still stores the new password as if rotation succeeded. Operators will then retrieve and distribute a password that does not actually work on the target host.

#### Recommendation
Fail closed: verify the exit status of every remote command before writing to the database, and stop or roll back the operation on the first failure. Ideally, batch all updates in a transaction so the database reflects only successfully applied rotations.
