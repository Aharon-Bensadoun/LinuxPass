# Code Review Findings — 2026-08-08 (Pass 10)

## Confirmed finding: password rotation is triggered through a GET endpoint

- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:208`

### Summary
`ServersController.Rotate(int id)` performs a state-changing password rotation operation, but the action is exposed as a plain GET endpoint and is not protected by antiforgery validation. Any page, email, or third-party site that causes the victim’s browser to request `/Servers/Rotate/{id}` can trigger a password rotation as soon as the authenticated user loads that resource.

### Why this matters
State-changing operations must not be reachable through GET. Browsers, crawlers, link previewers, and malicious pages can all initiate GET requests without explicit user intent. Because the application uses cookie-based authenticated sessions, the victim’s browser will attach its session automatically, turning this into a CSRF issue that can rotate credentials on managed servers unexpectedly.

### Evidence
The action has no `[HttpPost]` or `[ValidateAntiForgeryToken]` attributes and immediately invokes the rotation workflow:

```csharp
public async Task<IActionResult> Rotate(int id)
{
    var server = await _context.Servers.FindAsync(id);
    string sshKey = _configuration["SSHKeyPath"] ?? "";
    if (server != null)
    {
        var servers = await _context.Servers.ToListAsync();
        var resetPassService = new ResetPassService(_context, _configuration);
        string result = await resetPassService.ResetPass(server.HostSrvName, server.HostSrvUsername, sshKey);
```

### Recommended remediation
- Change `Rotate` to a POST-only action.
- Add `[ValidateAntiForgeryToken]` and invoke it from a form submission rather than a hyperlink.
- Consider requiring an explicit confirmation step before rotating production credentials.
