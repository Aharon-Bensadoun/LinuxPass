# Follow-up code review findings

## 1. CSRF on password disclosure by SMS (`PasswordsController.SendSMS`)
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:172`, `LinuxPass/Views/Passwords/Details.cshtml:77`
- **Severity:** High
- **Issue:** `SendSMS` is a state-changing POST endpoint that decrypts a stored password and sends it to an arbitrary phone number supplied by the request, but the action is missing `[ValidateAntiForgeryToken]`. The corresponding form also omits the anti-forgery token helper. Because the whole site only requires an authenticated browser session, any external site can force a logged-in user to submit this form and exfiltrate credentials over SMS to an attacker-controlled number.
- **Impact:** A CSRF attack can trigger out-of-band disclosure of managed credentials without the operator intentionally using the feature.
- **Recommendation:** Add `[ValidateAntiForgeryToken]` to `SendSMS`, emit `@Html.AntiForgeryToken()` in the form, and consider re-authentication or stronger authorization before sending decrypted secrets off-platform.

## 2. Password rotation exposed as a GET request (`ServersController.Rotate`)
- **Location:** `LinuxPass/Controllers/ServersController.cs:190`, `LinuxPass/Views/Servers/Index.cshtml:70`
- **Severity:** High
- **Issue:** Password rotation is implemented as a GET action and invoked from a plain anchor tag. GET requests must be safe and idempotent, but this endpoint resets passwords on remote systems and writes new secrets to the database. This makes the operation triggerable by link prefetching, crawlers, browser previews, or CSRF-style cross-site navigation.
- **Impact:** Simply visiting or preloading a URL can rotate every managed password for a server, causing unexpected outages and generating new credentials without operator intent.
- **Recommendation:** Change rotation to POST only, protect it with anti-forgery validation, and invoke it from a form with explicit user confirmation.

## 3. Managed passwords are orphaned from operating-system reality on delete
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:157`
- **Severity:** Medium
- **Issue:** Deleting a password record only removes the database entry. The corresponding operating-system account created by `AddUserService.AddUser` is not disabled, deleted, or rotated. This breaks the inventory/control relationship the application appears to provide: operators can believe an account has been removed while the remote login remains active with the previously issued password.
- **Impact:** Stale privileged or semi-privileged accounts can persist on target servers after being "deleted" in the UI, undermining deprovisioning and auditability.
- **Recommendation:** Either remove/disable the remote account during deletion, or clearly rename the action and UI to indicate it only deletes the local record. Preferably require a remote cleanup step and surface failures back to the operator.

## 4. Server deletion leaves residual access paths on remote hosts
- **Location:** `LinuxPass/Controllers/ServersController.cs:175`
- **Severity:** Medium
- **Issue:** Deleting a server record only removes the database row. Earlier provisioning via `AddServerService.ResetPass` grants sudo privileges and appends a trusted SSH public key on the remote host, but no corresponding cleanup happens on deletion. The application can therefore forget a server while the elevated trust relationship it established remains in place.
- **Impact:** Residual admin access may survive after a server is supposedly removed from management, increasing long-term blast radius and complicating incident response.
- **Recommendation:** Either revoke the deployed SSH key/sudo configuration as part of deletion or document clearly that deletion is inventory-only and does not decommission remote access.
