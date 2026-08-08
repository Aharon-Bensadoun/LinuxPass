# Code Review Findings — 2026-08-08 (Pass 4)

## Scope
Focused review of credential handling, remote command execution, and password delivery flows in `LinuxPass`.

## Findings

### 1. Stored passwords are encrypted with deterministic AES and no integrity protection
- **Severity:** high
- **Files:** `LinuxPass/Services/CryptorService.cs:10-45`, `LinuxPass/Controllers/PasswordsController.cs:122`, `LinuxPass/Services/ResetPassService.cs:41`

#### Why this matters
`CryptorService` derives the AES key by padding/truncating the configured string and uses an all-zero IV for every encryption. This makes encryption deterministic: the same plaintext under the same key always produces the same ciphertext. It also provides no authenticity/integrity check, so ciphertext tampering is not detected cryptographically.

Because this application stores recoverable passwords, deterministic encryption leaks password equality across records and weakens the protection of the password vault if the database is exposed.

#### Evidence
- `aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));`
- `aesAlg.IV = new byte[16]; // Initialization vector with zeros`
- The routine is used to store generated passwords in both create and rotate/reset flows.

#### Recommendation
Use modern authenticated encryption with a unique random nonce/IV per record, e.g. AES-GCM or an encrypt-then-MAC construction provided by a vetted library. Store the nonce alongside the ciphertext, and derive keys with a KDF or load a binary key from secure configuration instead of padding/truncating an arbitrary string.

---

### 2. User-controlled values are interpolated directly into privileged shell commands
- **Severity:** high
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:96-123`, `LinuxPass/Services/AddUserService.cs:17-37`, `LinuxPass/Services/AddServerService.cs:16-35`

#### Why this matters
The application takes values from HTTP-bound models such as `Password.Username`, `Password.Servername`, and `Server.HostSrvUsername`, then inserts them directly into shell command strings executed remotely via SSH with `sudo` privileges.

Examples:
- `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `echo '{username} ALL=(ALL) NOPASSWD:ALL' | ...`
- `... | sudo tee /etc/sudoers.d/{username}`

No server-side validation restricts these fields to safe Linux account/host patterns before command construction. A malicious authenticated user could supply shell metacharacters or crafted values that alter the remote command, potentially achieving arbitrary command execution as a privileged user on managed hosts.

#### Recommendation
Do not build shell commands with string interpolation from request data. Strictly validate usernames/hostnames against allowlisted patterns, and pass arguments through safe escaping or APIs that avoid invoking a shell. For sudoers management, write fixed-format files with validated identifiers only.

---

### 3. The SMS password delivery flow leaks secrets in the request URL
- **Severity:** high
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:172-195`, `LinuxPass/Services/SendSMSService.cs:14-32`

#### Why this matters
The `SendSMS` action decrypts the stored password and passes it to `SendSMSService`, which appends the plaintext password directly into the query string of an outbound GET request:

- `string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}...";`
- `HttpResponseMessage response = await client.GetAsync(url);`

Secrets placed in URLs are commonly exposed through proxy logs, application logs, browser/network tooling, monitoring systems, and third-party provider access logs. The password value is also concatenated without URL-encoding, which can additionally corrupt the request if the password contains reserved characters.

#### Recommendation
Do not send plaintext passwords via SMS at all if avoidable. Prefer an out-of-band one-time retrieval or reset flow. If messaging is absolutely required, use a POST request body over TLS and avoid including secrets in URLs, logs, or provider-visible metadata.

---

### 4. Error handling returns raw exception details to end users
- **Severity:** medium
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:63-80`

#### Why this matters
When decryption or another error occurs in `Details`, the controller returns `Problem($"error: {ex}")`, which includes the full exception object in the HTTP response. This can reveal stack traces, configuration mistakes, crypto errors, and implementation details useful to an attacker.

#### Recommendation
Return a generic user-facing error message and log the detailed exception server-side through the application logging pipeline.
