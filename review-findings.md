# Code Review Findings

## 1. Any authenticated user can rotate passwords for every account on a server via a GET request
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:208`
- **Issue:** `Rotate(int id)` is exposed as a GET action and has no anti-forgery protection or role-based restriction. Because the app applies only a global `RequireAuthenticatedUser` policy, any signed-in user who can reach the application can trigger a full password rotation on a managed server by visiting a URL or by being lured to a malicious page that loads that URL.
- **Impact:** This is a high-impact CSRF/authorization issue: rotating every managed account password on a server is an administrative action that can immediately disrupt operations and lock legitimate users out.
- **Recommendation:** Make rotation a POST-only action, add `[ValidateAntiForgeryToken]`, and restrict it to an administrator role/group/policy. Also consider adding an explicit confirmation workflow and audit logging.

## 2. The SMS endpoint sends decrypted passwords over query strings and without CSRF protection
- **Severity:** High
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:172`, `LinuxPass/Services/SendSMSService.cs:22`
- **Issue:** `SendSMS` is a POST action but lacks `[ValidateAntiForgeryToken]`. It decrypts the stored password and passes it to `SendSMSService`, which appends the plaintext password to a GET query string (`...SMSMessage={encodedMessage}{decryptedPassword}&...`). Query strings are commonly logged by reverse proxies, application telemetry, browser history, and third-party SMS providers.
- **Impact:** An attacker can potentially trigger password disclosure via CSRF, and the plaintext secret may be exposed in logs and downstream infrastructure even during legitimate use.
- **Recommendation:** Add anti-forgery validation, treat SMS sending as a privileged action, and never place secrets in URLs. If this feature must remain, send the payload in an HTTPS POST body to a trusted provider and avoid transmitting raw passwords at all if possible.

## 3. Password encryption uses a static zero IV, making ciphertext deterministic
- **Severity:** High
- **Location:** `LinuxPass/Services/CryptorService.cs:12-13`, `LinuxPass/Services/CryptorService.cs:31-32`
- **Issue:** AES encryption is performed with a key derived by padding/truncating the configured string, and the IV is always set to `new byte[16]`. Reusing a fixed IV causes identical plaintexts encrypted with the same key to produce identical ciphertexts.
- **Impact:** This leaks password equality patterns across records and weakens confidentiality. It also bypasses standard key-derivation practices and makes the crypto scheme brittle if configuration values are low entropy.
- **Recommendation:** Use an authenticated encryption scheme with a random per-record nonce/IV (for example AES-GCM or AES-CBC + HMAC with a unique IV), store the nonce alongside the ciphertext, and derive keys with a proper KDF if the source material is not already a raw cryptographic key.

## 4. Production hardening is incomplete because HSTS is explicitly disabled
- **Severity:** Medium
- **Location:** `LinuxPass/Program.cs:30`
- **Issue:** In the non-development pipeline, `UseHsts()` is commented out. Although `UseHttpsRedirection()` is enabled, browsers that first reach the site over HTTP are still vulnerable to SSL stripping until they have seen a valid redirect.
- **Impact:** Network attackers can interfere with first-contact traffic more easily than necessary, weakening transport security for an application that handles privileged credentials.
- **Recommendation:** Re-enable HSTS in production with an appropriate max-age and preload/includeSubDomains settings if operationally suitable.

## 5. Server passwords are accepted from clients and then written back to the database in plaintext during edit
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:116-147`, `LinuxPass/Models/Server.cs:10-12`
- **Issue:** The edit action binds `HostSrvPassword` from the posted form and then calls `_context.Update(server)`. Because `Server` contains a `HostSrvPassword` property, the submitted administrative password is persisted directly to the `Servers` table. The create action avoids this by copying only selected fields into a new entity, but the edit action does not.
- **Impact:** Administrative server credentials can be stored in plaintext in the application database, dramatically increasing blast radius after any database compromise or accidental data exposure.
- **Recommendation:** Do not persist `HostSrvPassword` at all. Use a dedicated view model for transient form input, exclude secret fields from the entity model/database, and explicitly map only non-secret properties back into tracked entities.

## 6. Deletion endpoints remove database records without revoking access on the target servers
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:145-157`, `LinuxPass/Controllers/ServersController.cs:188-200`
- **Issue:** Deleting a password record or a server record only removes the local database row. No SSH action is performed to disable/delete the Linux user account, rotate credentials, or otherwise reconcile the real infrastructure state.
- **Impact:** Operators can believe access has been revoked when the account or server-side credentials remain active. This creates orphaned privileged access and weakens auditability.
- **Recommendation:** Either implement actual deprovisioning/revocation workflows or clearly relabel these actions as metadata deletion only. For security-sensitive systems, the UI should not imply that deleting the record removes server access unless it truly does.
