# Code Review Findings — Follow-up 14

## Scope
- Repository: `Aharon-Bensadoun/LinuxPass`
- Base branch reviewed: `master`
- Review date: 2026-08-08

## Findings

### 1. High — `Rotate` performs a state-changing password reset over GET without CSRF protection
**Location:** `LinuxPass/Controllers/ServersController.cs:180`

`ServersController.Rotate(int id)` resets passwords on a remote host and writes new encrypted credentials to the database, but the action is exposed as a plain GET endpoint and has no `[ValidateAntiForgeryToken]` protection. Any page the authenticated user visits can trigger `/Servers/Rotate/{id}` through an image, iframe, or redirect, causing an unintended fleet-wide password rotation.

Because this action changes server-side state and affects remote accounts, it should only be callable through POST (or another non-GET verb) with antiforgery validation.

### 2. High — `SendSMS` accepts forged cross-site requests and exfiltrates decrypted passwords
**Location:** `LinuxPass/Controllers/PasswordsController.cs:151`

`PasswordsController.SendSMS` is a POST action, but it is missing `[ValidateAntiForgeryToken]`. The action decrypts the stored password server-side and sends it to an arbitrary `smsPhone` value supplied by the request. That means any site can submit a cross-site form on behalf of a logged-in operator and cause credentials to be sent to an attacker-controlled phone number.

This is especially severe because the action reveals the secret to an external channel rather than just mutating local state.

### 3. Medium — server edit failures are silently reported as success
**Location:** `LinuxPass/Controllers/ServersController.cs:116-149`

In `ServersController.Edit`, the result from `addServerService.ResetPass(...)` is checked, but only the success path performs `_context.Update(server)` and `SaveChangesAsync()`. When the SSH operation fails, the method skips the update yet still falls through to `return RedirectToAction(nameof(Index));` with no error message.

As a result, operators are redirected as if the edit succeeded even though the remote operation failed and no local update was persisted. This can leave the UI inconsistent with the actual server state and makes operational failures easy to miss.

## Validation
- `dotnet build LinuxPass.sln` ✅
  - Build succeeds.
  - Existing warnings remain, including `NU1902` on `Microsoft.Identity.Web` and Razor nullability warnings.
