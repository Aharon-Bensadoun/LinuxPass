# Code review findings (follow-up 4)

## 1. Stored passwords can be disclosed by any authenticated user
- **Severity**: high
- **Evidence**:
  - `LinuxPass/Program.cs:14-20` applies a global `RequireAuthenticatedUser()` policy, but no role- or claim-based restriction is added for sensitive controllers.
  - `LinuxPass/Controllers/PasswordsController.cs:20-42` allows any authenticated user to list all password records and search by username/server.
  - `LinuxPass/Controllers/PasswordsController.cs:45-73` decrypts and returns the selected password in the details view.
  - `LinuxPass/Controllers/PasswordsController.cs:174-195` lets any authenticated user trigger SMS delivery of the decrypted password.
- **Impact**: Any Azure AD / Identity account that can sign in to the app can enumerate managed accounts, decrypt stored credentials, and exfiltrate them by reading the details page or by invoking the SMS endpoint. This breaks least privilege and turns a simple application login into full access to every managed server account password stored by the platform.
- **Recommendation**: Restrict password-management endpoints with explicit authorization policies (for example admin/helpdesk roles or narrow claims), and separately protect password reveal / SMS actions with stronger authorization and auditing.

## 2. Password rotation continues after remote failures and stores unusable credentials
- **Severity**: high
- **Evidence**:
  - `LinuxPass/Services/ResetPassService.cs:36-54` creates `echo '{user}:{password}' | sudo chpasswd`, executes it, but never checks `command.ExitStatus` or `command.Error` before persisting the generated password.
  - The same block immediately encrypts the locally generated password and saves it to the database with `_context.Add(newpassword); await _context.SaveChangesAsync();` even if the remote `chpasswd` command failed.
  - `LinuxPass/Controllers/ServersController.cs:216-227` treats the service result `"Success"` as a successful rotation for the whole server.
- **Impact**: If `sudo chpasswd` fails for one or more accounts (sudo policy issue, shell quoting problem, account lock, disk full, transient SSH problem), the application still records new passwords that were never applied on the target host. Operators will then trust and distribute incorrect credentials while the real server passwords remain unchanged, causing account lockouts, failed incident response, and loss of administrative access during emergencies.
- **Recommendation**: Check the exit status of every remote password-reset command before saving anything, stop on first failure or record per-account failure explicitly, and wrap the database updates so local state cannot drift from the actual remote state.
