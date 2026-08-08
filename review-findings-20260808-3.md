# Code Review Findings — 2026-08-08 (Follow-up 3)

## 1. Stored passwords can be deleted without revoking the corresponding remote Linux account
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:146-157`

### Why this matters
`DeleteConfirmed` removes the password record from the database, but it never disables or deletes the matching account on the target server. An operator can therefore believe an account was removed from LinuxPass while the credential and account remain active on the host.

This creates a dangerous desynchronization between the inventory and the real access state: audits based on the UI will miss still-valid server accounts, and incident responders may falsely conclude that access has been revoked.

### Evidence
```csharp
[HttpPost, ActionName("Delete")]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteConfirmed(int id)
{
    var password = await _context.Passwords.FindAsync(id);
    if (password != null)
    {
        _context.Passwords.Remove(password);
    }

    await _context.SaveChangesAsync();
    return RedirectToAction(nameof(Index));
}
```

### Recommended fix
Before deleting the database record, revoke the remote account or at minimum lock it on the target host, and fail the request if remote revocation fails. If the intended behavior is only archival cleanup, rename the action so operators do not mistake it for account deprovisioning.

## 2. Server deletion leaves privileged access behind on managed hosts
- **Severity:** high
- **Location:** `LinuxPass/Controllers/ServersController.cs:176-187`

### Why this matters
Deleting a server entry only removes the database row. It does not remove the previously granted sudoers entries or the trusted SSH key material that `AddServerService.ResetPass` installed on the host. As a result, LinuxPass can lose track of a machine while its management backdoor remains deployed.

This is especially risky because onboarding explicitly grants `NOPASSWD:ALL` and writes additional sudoers configuration. Removing the inventory record without cleanup makes later detection and rollback much harder.

### Evidence
```csharp
[HttpPost, ActionName("Delete")]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteConfirmed(int id)
{
    var server = await _context.Servers.FindAsync(id);
    if (server != null)
    {
        _context.Servers.Remove(server);
    }

    await _context.SaveChangesAsync();
    return RedirectToAction(nameof(Index));
}
```

Related provisioning logic:
```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
...
var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && echo '{pubkey}' | cat >> ~/.ssh/test");
```

### Recommended fix
Implement a server offboarding workflow that removes the LinuxPass-managed sudoers entries and authorized keys from the remote host before deleting the local record. If remote cleanup cannot be guaranteed, block deletion and surface a clear error.

## 3. Full exception details are returned to authenticated users
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:80`

### Why this matters
When password decryption fails, the controller returns the full exception object in the HTTP response. Exception strings often include stack traces, configuration mistakes, crypto failure details, and other implementation data that helps an attacker understand the environment.

Any authenticated user who can trigger a decryption error can harvest internal diagnostics directly from the application.

### Evidence
```csharp
catch (Exception ex)
{
    return Problem($"error: {ex}");
}
```

### Recommended fix
Log the exception server-side and return a generic error message to the client, such as `return Problem("Failed to load password details.");`. Avoid exposing raw exception text in MVC responses.
