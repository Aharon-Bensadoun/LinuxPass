# Code Review Findings — Follow-up 2026-08-08

This follow-up documents additional findings confirmed from the current codebase, excluding the issues already captured previously.

## 1. Server bootstrap and password reset commands are vulnerable to shell injection
- **Severity:** high
- **Confidence:** high

### Evidence
`AddServerService.ResetPass` interpolates `hostname`, `username`, and the contents of the configured public key file directly into shell commands executed over SSH:

```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
...
string pubkey = File.ReadAllText(pubkeypath);
var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && echo '{pubkey}' | cat >> ~/.ssh/test");
```

Source: `LinuxPass/Services/AddServerService.cs:21-33`

`ResetPassService.ResetPass` also interpolates discovered account names and generated passwords directly into a shell command:

```csharp
var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
```

Source: `LinuxPass/Services/ResetPassService.cs:35-43`

The values above are not shell-escaped before being embedded in single-quoted shell fragments. A username, public key, or other input containing a single quote can break out of the quoted string and inject arbitrary shell syntax on the target server.

### Impact
An attacker able to influence one of these values can execute arbitrary commands on managed Linux hosts with the privileges of the SSH session, and in multiple cases under `sudo`. Because these code paths modify `/etc/sudoers`, create files under `/etc/sudoers.d`, and run `chpasswd`, successful injection can lead directly to host compromise.

### Recommendation
Avoid building shell commands through string interpolation. Use safer remote execution patterns that pass data as arguments instead of shell fragments, or apply strict allow-list validation for hostnames and usernames plus robust shell escaping for any value that must cross a shell boundary. Public key material should be transferred as file content rather than echoed through a shell command.

## 2. Sensitive credentials are returned to the client in raw error messages
- **Severity:** medium
- **Confidence:** high

### Evidence
Several service methods catch exceptions and return `ex.Message` directly:

```csharp
catch (Exception ex)
{
    return (ex.Message);
}
```

Sources:
- `LinuxPass/Services/AddServerService.cs:39-42`
- `LinuxPass/Services/ResetPassService.cs:58-61`
- `LinuxPass/Services/SendSMSService.cs:37-40`

Those returned strings are then surfaced to end users via controller `ViewData["Message"]` / `ViewData["ErrorMessage"]` assignments, for example:

```csharp
string result = addServerService.ResetPass(server.HostSrvName, server.HostSrvUsername, server.HostSrvPassword);
...
ViewData["Message"] = result;
```

Source: `LinuxPass/Controllers/ServersController.cs:88-104`

and:

```csharp
string result = await resetPassService.ResetPass(server.HostSrvName, server.HostSrvUsername, sshKey);
if (result != "Success")
{
    ViewData["ErrorMessage"] = result;
}
```

Source: `LinuxPass/Controllers/ServersController.cs:210-218`

When the underlying SSH or HTTP libraries raise errors, exception messages commonly include the destination hostname, username, filesystem paths, request URLs, or other operational details. In this application, `ServersController.Create` and `Edit` also accept `HostSrvPassword` from users, so failures on those paths risk reflecting sensitive connection context back into the rendered page.

### Impact
Authenticated users can receive internal infrastructure details and potentially sensitive connection information that should remain server-side. This increases the blast radius of ordinary operational failures and helps an attacker map the environment or recover secrets accidentally included in exception text.

### Recommendation
Log detailed exception information only on the server side and return a generic user-facing error message. Introduce structured logging around SSH/SMS failures and ensure views never render raw exception text.
