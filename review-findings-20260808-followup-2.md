# Code review findings follow-up 2

## 1. Static AES IV makes identical passwords encrypt to identical ciphertext
- Severity: high
- Location: `LinuxPass/Services/CryptorService.cs:13-14`, `LinuxPass/Services/CryptorService.cs:33-34`
- Details: `CryptorService` always uses `new byte[16]` as the AES IV for both encryption and decryption. This makes encryption deterministic: the same plaintext under the same key always produces the same ciphertext. Because the application stores many generated passwords in the database, this leaks when two accounts share the same password value and removes an important security property expected from AES-CBC-style encryption.
- Impact: An attacker with database access can correlate repeated passwords across users/servers and gains a much better starting point for offline analysis.
- Recommendation: Generate a fresh random IV for every encryption, prepend/store it with the ciphertext, and authenticate the ciphertext with an AEAD mode such as AES-GCM (or at minimum add integrity protection).

## 2. Server-side password reset can be triggered with a GET request and no anti-forgery protection
- Severity: high
- Location: `LinuxPass/Controllers/ServersController.cs:191-211`
- Details: `ServersController.Rotate(int id)` performs a state-changing action that connects over SSH, resets passwords for all users on a host, and persists new password records. The action is not restricted to POST and has no `[ValidateAntiForgeryToken]`. Because the app applies only an authentication policy globally, any authenticated user can be tricked into visiting `/Servers/Rotate/{id}` and unintentionally trigger a rotation.
- Impact: Cross-site request forgery can force password rotation on managed servers, causing outages and credential churn without the victim’s intent.
- Recommendation: Make this a POST-only endpoint, require an anti-forgery token, and consider an authorization policy/role check because this is a highly privileged operation.

## 3. Delete endpoint removes only the database record and leaves the remote account untouched
- Severity: medium
- Location: `LinuxPass/Controllers/PasswordsController.cs:155-168`
- Details: `DeleteConfirmed` removes the `Password` row from the database but does not call any remote provisioning/deprovisioning workflow. Earlier in the controller, `Create` provisions an account on the target server through `AddUserService.AddUser(...)`. As a result, deleting a password entry does not delete or disable the corresponding OS account and creates a false sense that access was removed.
- Impact: Orphaned remote accounts can remain active after operators believe they were deleted from the system.
- Recommendation: Either implement matching remote deprovisioning/disable logic as part of deletion, or clearly separate “remove record” from “remove server access” in the UI and workflow.

## 4. Password rotation is non-atomic and can leave server credentials changed without a matching database state
- Severity: high
- Location: `LinuxPass/Services/ResetPassService.cs:34-53`
- Details: Inside the loop, the code first executes `sudo chpasswd` on the remote host and then inserts the encrypted password into the database with `SaveChangesAsync()`. If a later database write fails, earlier users have already had their server password changed but the application no longer has a consistent record of the new credential set. The method also partially commits each user independently, which amplifies inconsistency during mid-run failures.
- Impact: The system can lock operators out of managed accounts or store only a subset of rotated credentials, leaving recovery to manual intervention.
- Recommendation: Redesign rotation as a transactional workflow: stage all generated credentials first, commit database state atomically, and only then finalize remote changes; or record durable recovery/audit information and explicit partial-failure handling so the system can reconcile safely.

## 5. SMS sender puts the decrypted password in the query string
- Severity: high
- Location: `LinuxPass/Services/SendSMSService.cs:23-30`
- Details: `SendSMSAsync` builds a GET URL that embeds the plaintext password directly in the `SMSMessage` query parameter. Query strings are commonly logged by reverse proxies, application logs, browser/network tooling, and third-party SMS gateways. The code also only URL-encodes the static prefix, not the password value appended after it.
- Impact: Plaintext passwords can be exposed in multiple logging and monitoring layers outside the application’s control.
- Recommendation: Never send passwords through a GET query string. Use a POST body to the provider API if SMS must remain supported, encode the full payload correctly, and prefer sending a one-time reset link/code rather than the actual password.
