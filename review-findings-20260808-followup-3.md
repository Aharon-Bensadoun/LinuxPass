# Code review findings — follow-up 3

## 1. Password deletion only removes the database row, leaving the remote Linux account active
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:157`
- **Why it matters:** `DeleteConfirmed` deletes only the `Passwords` record. It never disables or removes the corresponding remote account from the target server. After an operator clicks delete, the UI suggests the credential is gone, but the Linux user created by `AddUserService` can still exist on the host and continue to authenticate with the last rotated password.
- **Suggested fix:** Either remove/lock the remote account as part of the delete workflow, or rename the action and UX to clarify that it only deletes the stored secret history and does not revoke server access.

## 2. Server deletion leaves all dependent credentials orphaned
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/ServersController.cs:196`
- **Why it matters:** `ServersController.DeleteConfirmed` removes a server without checking for related `Passwords` rows keyed by `Servername`. If the database schema does not enforce cascading cleanup, this produces orphaned secrets that still appear in password listings and can still be decrypted even though the corresponding server entry no longer exists.
- **Suggested fix:** Enforce a real relationship between servers and passwords, block deletion when credentials still exist, or explicitly clean up dependent password records in the same transaction.

## 3. Password rotation is triggered by a GET link and can be replayed accidentally
- **Severity:** high
- **Location:** `LinuxPass/Controllers/ServersController.cs:210`, `LinuxPass/Views/Servers/Index.cshtml:53`
- **Why it matters:** rotation is a state-changing, security-sensitive operation, but it is exposed as a plain `<a>` link to `Rotate(int id)`. Because the action is a GET, it can be triggered by crawlers, link previewers, browser prefetching, or a cross-site request, causing unexpected password resets across a server.
- **Suggested fix:** make rotation a POST-only action, require an anti-forgery token, and invoke it from a form with an explicit confirmation step.

## 4. The SMS secret-sharing endpoint is missing anti-forgery protection
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:169`, `LinuxPass/Views/Passwords/Details.cshtml:77`
- **Why it matters:** the details page posts to `SendSMS`, but the action lacks `[ValidateAntiForgeryToken]`. Any site the authenticated operator visits can auto-submit a form to this endpoint and exfiltrate the decrypted password to an attacker-controlled phone number, because the controller decrypts the stored secret server-side before sending it.
- **Suggested fix:** add `[ValidateAntiForgeryToken]` to `SendSMS` and emit the token in the form. Consider additional authorization and auditing for out-of-band secret delivery.

## 5. Encryption uses a static zero IV, making ciphertext deterministic
- **Severity:** high
- **Location:** `LinuxPass/Services/CryptorService.cs:12`, `LinuxPass/Services/CryptorService.cs:31`
- **Why it matters:** AES is initialized with `aesAlg.IV = new byte[16]` for every encryption. This means identical plaintext passwords encrypted under the same key always produce identical ciphertext, leaking equality information and violating basic CBC-mode requirements. It also makes the scheme non-standard and harder to migrate safely.
- **Suggested fix:** generate a fresh random IV per encryption, store it alongside the ciphertext, and prefer an authenticated construction such as AES-GCM or the ASP.NET Core data protection APIs.
