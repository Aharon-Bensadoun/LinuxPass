# Code Review Findings — Round 5

## Finding 1: Passwords are encrypted deterministically with a fixed zero IV
- **Severity:** High
- **Location:** `LinuxPass/Services/CryptorService.cs:14-16`, `LinuxPass/Services/CryptorService.cs:35-37`

### Why this is a problem
`EncryptString` derives the AES key by padding/truncating the configured secret and then always uses `new byte[16]` as the IV. Reusing a constant IV makes encryption deterministic: identical plaintext passwords encrypted under the same key always produce the same ciphertext. Because the application stores many generated server passwords in the database, anyone with read access to that table can correlate reused passwords across accounts and servers and build equality or frequency attacks against the stored secrets. This defeats one of the primary goals of encrypting the password column in the first place.

### Recommended fix
Generate a fresh random IV for every encryption, prepend/store it alongside the ciphertext, and use an authenticated mode such as AES-GCM (or at minimum AES-CBC plus an HMAC). Derive the key with a proper KDF instead of `PadRight(...).Substring(...)`.

## Finding 2: Passwords are sent to the SMS gateway in the query string
- **Severity:** High
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:180-193`, `LinuxPass/Services/SendSMSService.cs:24-32`

### Why this is a problem
`SendSMS` decrypts the stored password and passes it to `SendSMSAsync`, which appends the cleartext password directly into the request URL as the `SMSMessage` query parameter before issuing an HTTP GET. Query strings are routinely logged by reverse proxies, web servers, APM tools, browser history, and third-party providers. That means every password sent by SMS is also likely to be copied into logs outside the application’s control, creating a second long-lived disclosure channel even if the SMS provider itself is trusted.

### Recommended fix
Do not transport secrets in URLs. If SMS delivery is still required, send the payload in the body of a POST request over HTTPS and ensure the provider contract explicitly avoids logging sensitive fields. Prefer replacing password disclosure over SMS with an out-of-band reset flow or one-time retrieval mechanism.

## Finding 3: Unvalidated usernames are interpolated into privileged shell commands
- **Severity:** High
- **Location:** `LinuxPass/Services/AddUserService.cs:17-30`

### Why this is a problem
`AddUser` builds a shell command with string interpolation: `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`. The `username` value comes from the MVC form in `PasswordsController.Create` and is never validated against a safe character set before being embedded in the remote shell command. An authenticated user can submit shell metacharacters (for example `bob; curl ...`) and have them executed on the managed server with the SSH account’s privileges, which is likely root-equivalent in this application’s deployment model.

### Recommended fix
Reject any username that does not match a strict allowlist for Linux account names before invoking SSH (for example `^[a-z_][a-z0-9_-]{0,31}$`). Avoid shell string concatenation entirely where possible, or escape every argument with a robust shell-escaping routine before constructing commands.

## Finding 4: Adding a server permanently grants passwordless sudo to the remote account
- **Severity:** High
- **Location:** `LinuxPass/Services/AddServerService.cs:24-35`

### Why this is a problem
When onboarding a server, `AddServerService.ResetPass` modifies `/etc/sudoers` and creates `/etc/sudoers.d/{username}` entries that grant the provided remote account `NOPASSWD:ALL`. This is a persistent privilege-escalation backdoor, not a temporary bootstrap step. Any compromise of that account afterwards gives an attacker unrestricted root access on the managed host, and the application never removes or scopes down the privilege it added.

### Recommended fix
Do not grant blanket `NOPASSWD:ALL`. Use a dedicated automation account provisioned out-of-band with the minimum sudo rules required for the exact management commands, or require administrators to preconfigure least-privilege access before the host is registered.
