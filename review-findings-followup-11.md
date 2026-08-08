# Code Review Findings Follow-up 11

## 1. Critical: deterministic AES encryption leaks when two accounts share the same password
- **Location:** `LinuxPass/Services/CryptorService.cs:13-14`, `LinuxPass/Services/CryptorService.cs:33-34`
- **Why this is a problem:** `EncryptString` and `DecryptString` use a fixed all-zero IV (`aesAlg.IV = new byte[16]`) for every encryption. This makes AES encryption deterministic: the same plaintext encrypted with the same key always yields the same ciphertext. Since the application stores many generated account passwords in the database, an operator with DB access can immediately detect password reuse across users or servers by comparing ciphertext values, which defeats an important confidentiality property for stored secrets.
- **Impact:** Password equality leaks across all records, and any future reuse or collisions become trivially searchable directly in the `Passwords` table.
- **Recommended fix:** Generate a fresh random IV per encryption, prefix/store it alongside the ciphertext, and read it back during decryption. Prefer an authenticated mode such as AES-GCM, or at least store `IV || ciphertext` and add integrity protection.

## 2. High: password generation uses `System.Random`, making generated credentials predictable
- **Location:** `LinuxPass/Services/PassGenService.cs:7`, `LinuxPass/Services/PassGenService.cs:31-34`
- **Why this is a problem:** All Linux account passwords are produced by `PassGenService.GeneratePassword`, but the implementation relies on a process-wide `System.Random`. `System.Random` is not a cryptographically secure RNG and is predictable from internal state. Anyone able to observe enough outputs, or even approximate process start timing, can significantly reduce the search space for subsequently generated passwords.
- **Impact:** Newly created or rotated Linux passwords are weaker than intended and may be guessable by an attacker who can model or infer the PRNG state.
- **Recommended fix:** Replace `Random` with `RandomNumberGenerator` (for example `RandomNumberGenerator.GetInt32`) and keep the password generator fully CSPRNG-based.

## 3. High: state-changing password rotation is exposed as a GET action with no anti-forgery protection
- **Location:** `LinuxPass/Controllers/ServersController.cs:184-204`, `LinuxPass/Views/Servers/Index.cshtml:61-63`
- **Why this is a problem:** The `Rotate` action changes remote passwords and inserts new password records, but it is reachable via a plain anchor tag (`<a asp-action="Rotate" ...>`), which issues a GET request. Because the app uses cookie-based authentication (`AddMicrosoftIdentityWebAppAuthentication`), any authenticated user's browser can be induced to load `/Servers/Rotate/{id}` from another site, triggering a password rotation without user intent. There is no `[HttpPost]` nor `[ValidateAntiForgeryToken]` on this action.
- **Impact:** Cross-site request forgery can rotate passwords on managed servers, causing operational disruption and unexpected credential changes.
- **Recommended fix:** Make `Rotate` a POST-only action, add anti-forgery validation, and invoke it from a form submission rather than a link.

## 4. High: user-controlled values are interpolated directly into shell commands executed as sudo on remote hosts
- **Location:** `LinuxPass/Services/AddUserService.cs:22`, `LinuxPass/Services/ResetPassService.cs:38`
- **Why this is a problem:** The application constructs remote shell commands by embedding variables directly into command strings. In `AddUserService`, the `username` and generated `password` are inserted into `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`. In `ResetPassService`, usernames collected from the remote host and generated passwords are inserted into `echo '{user}:{password}' | sudo chpasswd`. There is no shell escaping or strict input validation. A username containing shell metacharacters, quotes, command substitutions, or option prefixes can alter the command executed through SSH.
- **Impact:** A malicious or malformed username can break command execution or execute unintended commands with elevated privileges on managed Linux servers.
- **Recommended fix:** Strictly validate account names against a safe allowlist (for example Linux username rules), avoid shell interpolation, and pass data through safer mechanisms where possible.
