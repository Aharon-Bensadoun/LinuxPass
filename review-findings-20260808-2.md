# Code review findings

## 1. Password encryption is deterministic and lacks integrity protection
- **Severity:** High
- **Where:** `LinuxPass/Services/CryptorService.cs:11-36`
- **Issue:** The application encrypts passwords with AES using a key derived by truncating/padding the configured string and a fixed all-zero IV (`aesAlg.IV = new byte[16]`). This makes encryption deterministic: identical plaintexts under the same key produce identical ciphertexts. The implementation also provides no authentication/integrity check.
- **Impact:** An attacker with database access can identify password reuse across accounts/servers and can tamper with ciphertexts without detection. Because the same application key decrypts every stored password, compromise of the config or host yields bulk plaintext recovery.
- **Recommendation:** Replace this with authenticated encryption using a random per-record nonce/IV (for example AES-GCM or ASP.NET Core Data Protection for application-managed secrets). Store the nonce alongside the ciphertext and rotate away from the current format.

## 2. Password reset and user creation commands are vulnerable to shell injection
- **Severity:** Critical
- **Where:** `LinuxPass/Services/AddUserService.cs:21`, `LinuxPass/Services/ResetPassService.cs:35`, `LinuxPass/Services/AddServerService.cs:21,33`
- **Issue:** User-controlled or externally sourced values are interpolated directly into shell commands executed over SSH, e.g. `sudo useradd -m {username}`, `echo '{user}:{password}' | sudo chpasswd`, and sudoers/pubkey commands built with string interpolation.
- **Impact:** If an attacker can create or influence usernames, hostnames, or key content containing shell metacharacters/quotes, they can execute arbitrary commands on managed Linux hosts with elevated privileges. In `ResetPassService`, even a malicious local username already present on a target host could break quoting and trigger command execution during password rotation.
- **Recommendation:** Do not construct shell commands by concatenation. Strictly validate allowed usernames/hostnames against conservative regexes and pass data through safer mechanisms (for example uploading a script/input file, using `chpasswd` with stdin without shell interpolation, or escaping with a proven shell-escaping routine).

## 3. Sensitive password rotation action is exposed as a GET endpoint without CSRF protection
- **Severity:** High
- **Where:** `LinuxPass/Controllers/ServersController.cs:178-201`, `LinuxPass/Views/Servers/Index.cshtml:60-62`
- **Issue:** `Rotate(int id)` performs a state-changing operation (rotates passwords on a server and inserts new credentials into the database) through a GET action linked directly from the index page.
- **Impact:** Any page visited by an authenticated user can trigger server-wide password rotation via a simple cross-site request (image/link/prefetch). Because the action changes credentials on remote machines, accidental crawls or browser prefetching can also cause operational disruption.
- **Recommendation:** Require POST for rotation, add `[ValidateAntiForgeryToken]`, and invoke it from a form with an explicit confirmation step.

## 4. Application reveals full plaintext passwords in the UI and transmits them by SMS/URL query string
- **Severity:** High
- **Where:** `LinuxPass/Controllers/PasswordsController.cs:52-72,149-175`, `LinuxPass/Views/Passwords/Details.cshtml:48-91`, `LinuxPass/Services/SendSMSService.cs:21-30`
- **Issue:** The details page decrypts and renders the full password to any authenticated user. The SMS feature then sends that password through a GET request where the secret is embedded in the URL query string.
- **Impact:** Plaintext credentials are exposed in browser memory, copy/paste buffers, screenshots, and logs. Sending the password in the URL leaks it to reverse proxies, web server logs, browser history, monitoring systems, and potentially third-party SMS providers.
- **Recommendation:** Minimize plaintext exposure: use reveal-on-demand only for specifically authorized users, audit access, and avoid delivering passwords over SMS. If outbound delivery is absolutely required, use POST over TLS to a trusted provider API and never place secrets in URLs.

## 5. Overly broad authorization lets any authenticated user administer all servers and passwords
- **Severity:** High
- **Where:** `LinuxPass/Program.cs:15-20`, controllers under `LinuxPass/Controllers`
- **Issue:** The app enforces only `RequireAuthenticatedUser()` globally. There is no role-based restriction, object-level authorization, or per-server ownership check around viewing passwords, creating users, deleting credentials, adding servers, or rotating every account on a host.
- **Impact:** Any Azure AD user who can sign in gains full administrative capability over every stored secret and managed Linux server. In a typical enterprise tenant, this is a privilege-escalation path from ordinary SSO access to infrastructure administration.
- **Recommendation:** Introduce least-privilege authorization: admin roles/groups for server management, narrower roles for password viewing/rotation, and object-level checks tying users to allowed servers/accounts. Review every destructive/sensitive action.

## 6. Remote onboarding grants persistent passwordless sudo to managed accounts
- **Severity:** Critical
- **Where:** `LinuxPass/Services/AddServerService.cs:21-34`
- **Issue:** During server onboarding the code appends `'{username} ALL=(ALL) NOPASSWD:ALL'` to sudoers and creates an additional sudoers file, effectively granting full passwordless root access to the supplied account.
- **Impact:** Compromise of that account, its password, or the application’s SSH key yields immediate root access on the target server. This dramatically expands blast radius and defeats normal privilege separation.
- **Recommendation:** Avoid persistent `NOPASSWD:ALL`. Use a dedicated least-privilege automation account with only the specific commands required, preferably constrained by command allowlists, host restrictions, and audited key-based access.

## 7. Password generation uses non-cryptographic randomness
- **Severity:** Medium
- **Where:** `LinuxPass/Services/PassGenService.cs:7-33`
- **Issue:** Passwords are generated with `System.Random`, which is predictable and not suitable for secrets.
- **Impact:** Generated Linux account passwords may be guessable by an attacker who can infer PRNG state or observe enough outputs, especially under concurrent use.
- **Recommendation:** Use `RandomNumberGenerator`/`GetInt32` or another cryptographically secure RNG, and enforce character-class requirements explicitly.

## 8. Detailed exception messages are returned to clients
- **Severity:** Medium
- **Where:** `LinuxPass/Controllers/PasswordsController.cs:69-72`, multiple services returning raw `ex.Message`
- **Issue:** On decryption failure, the controller returns `Problem($"error: {ex}")`, which includes full exception details. Service methods also bubble raw exception messages into UI messages.
- **Impact:** Internal stack traces, crypto/configuration details, filesystem paths, SSH errors, and remote command output can be disclosed to authenticated users, aiding further attacks.
- **Recommendation:** Log detailed exceptions server-side only, and return generic user-safe error messages to the client.
