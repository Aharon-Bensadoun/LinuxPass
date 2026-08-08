# Code Review Findings Follow-up 9

## Finding 1: Anyone who can sign in can read every stored password
- Severity: high
- Confidence: high

### Evidence
- `LinuxPass/Program.cs:16-20` installs a global authorization policy that only requires an authenticated user.
- `LinuxPass/Controllers/PasswordsController.cs:24-47` returns password records from `_context.Passwords` with no per-user, per-role, or per-server ownership filter.
- `LinuxPass/Controllers/PasswordsController.cs:50-77` decrypts the selected password and returns it to the view for any authenticated caller who knows an `id`.
- `LinuxPass/Controllers/PasswordsController.cs:172-195` likewise decrypts the password again before sending it over SMS, still without any authorization check beyond being signed in.

### Impact
Any authenticated account in the application can enumerate password metadata from the index and open `Passwords/Details/{id}` to recover plaintext credentials for accounts and servers they do not own. In practice this collapses the app's access boundary to “has any account”, which is a critical confidentiality failure for a password-management workflow.

### Recommendation
Introduce object-level authorization before listing, viewing, deleting, rotating, or exporting credentials. At minimum, associate passwords and servers with an owning user/group and filter every query by that ownership. Sensitive actions such as decrypting or sending passwords should also require an explicit privileged role/policy instead of the current global “authenticated user” rule.

## Finding 2: SSH commands interpolate untrusted values directly into remote shell strings
- Severity: high
- Confidence: high

### Evidence
- `LinuxPass/Services/AddUserService.cs:24` builds `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd` using the request-supplied username and generated password without shell escaping.
- `LinuxPass/Services/AddServerService.cs:24` injects `username` into two sudoers-related shell fragments and `LinuxPass/Services/AddServerService.cs:34` injects the configured public key content into another shell command.
- `LinuxPass/Services/ResetPassService.cs:37` builds `echo '{user}:{password}' | sudo chpasswd` for each discovered account without escaping either field.
- The controller inputs feeding these services come from bound request models in `LinuxPass/Controllers/ServersController.cs:70-89`, `LinuxPass/Controllers/ServersController.cs:130-147`, and `LinuxPass/Controllers/PasswordsController.cs:96-131`.

### Impact
A crafted username, password, hostname-associated account value, or malformed public key containing shell metacharacters or quotes can break out of the intended command and execute arbitrary shell code on the managed Linux host under the SSH account's privileges. Because these commands invoke `sudo`, exploitation can become a full remote host compromise.

### Recommendation
Stop constructing shell commands with string interpolation. Validate account names against a strict allowlist (for example Linux username syntax), avoid passing secrets through shell pipelines, and prefer safer primitives such as uploading files directly, invoking narrowly scoped scripts with positional arguments that are properly escaped, or using APIs/libraries that do not require a shell.

## Finding 3: Server onboarding permanently grants passwordless sudo to the SSH account
- Severity: high
- Confidence: high

### Evidence
- `LinuxPass/Services/AddServerService.cs:24` executes:
  - `echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo`
  - `echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}`
- This happens as part of the normal `ServersController.Create` and `ServersController.Edit` flows in `LinuxPass/Controllers/ServersController.cs:70-89` and `LinuxPass/Controllers/ServersController.cs:130-147`.

### Impact
Every successful server enrollment modifies the target host so the specified SSH account gains unrestricted sudo, including passwordless sudo. That materially expands the blast radius of any compromise of the application, the configured SSH key, or the onboarded account itself. It also changes managed infrastructure state in a way that may violate least-privilege and compliance expectations.

### Recommendation
Do not grant blanket sudo from the web application. Use a pre-provisioned service account with only the minimal commands required, or require administrators to perform host bootstrap out of band. If privileged operations are unavoidable, constrain them to a tightly scoped sudoers profile and make the privilege grant explicit, reviewed, and reversible.

## Finding 4: Password disclosure over SMS is implemented as a GET request query string
- Severity: medium
- Confidence: high

### Evidence
- `LinuxPass/Controllers/PasswordsController.cs:172-195` decrypts the stored password and passes it to the SMS service.
- `LinuxPass/Services/SendSMSService.cs:25` appends the plaintext password to the URL query string: `?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone=...`.
- `LinuxPass/Services/SendSMSService.cs:31` then sends the request via `HttpClient.GetAsync(url)`.

### Impact
The full secret is exposed not only to the SMS provider but also to intermediary logs and telemetry that capture request URLs, such as reverse proxies, WAFs, APM tools, browser history during debugging, and outbound HTTP diagnostics. Even if SMS transmission were acceptable, placing the password in a GET query string causes avoidable secondary leakage channels.

### Recommendation
Remove the SMS password-sharing feature if possible. If a messaging integration must remain, never place secrets in URLs; use a POST body over HTTPS, minimize logging, and prefer one-time reset links or OTP flows over sending reusable passwords in plaintext.
