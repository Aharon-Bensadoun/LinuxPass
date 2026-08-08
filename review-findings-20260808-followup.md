# Code Review Findings — 2026-08-08 Follow-up

## 1. Any authenticated user can rotate passwords for every managed account on a server
- **Severity:** high
- **Confidence:** high
- **Location:** `LinuxPass/Controllers/ServersController.cs:208-228`, `LinuxPass/Services/ResetPassService.cs:24-55`

### Why this is a problem
The application enforces only a global `RequireAuthenticatedUser()` policy in `Program.cs`, but `ServersController.Rotate` has no additional authorization checks. Any signed-in user can call `/Servers/Rotate/{id}` and trigger `ResetPassService.ResetPass`, which logs into the target host and resets passwords for every local account with UID >= 1000 except a tiny hard-coded allowlist. This gives any authenticated account a direct way to forcibly rotate credentials for many users on production servers, which is a high-impact privilege escalation and denial-of-service vector.

### Evidence
`Rotate` is exposed as a plain controller action and immediately invokes the privileged reset routine:

```csharp
public async Task<IActionResult> Rotate(int id)
{
    var server = await _context.Servers.FindAsync(id);
    ...
    string result = await resetPassService.ResetPass(server.HostSrvName, server.HostSrvUsername, sshKey);
```

The reset routine then enumerates local users and resets each password:

```csharp
var listuser = client.CreateCommand("for user in $(cut -d: -f1 /etc/passwd); do [ $(id -u $user) -ge 1000 ] ... && echo $user; done");
...
var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
...
_context.Add(newpassword);
await _context.SaveChangesAsync();
```

### Recommended fix
Restrict this action to a dedicated administrative role or policy, make it a POST-only action protected by anti-forgery validation, and scope password rotation to explicitly approved managed accounts rather than every UID >= 1000 user on the host.

## 2. Passwords are appended unencoded into a GET query string when sent by SMS
- **Severity:** medium
- **Confidence:** high
- **Location:** `LinuxPass/Services/SendSMSService.cs:21-32`

### Why this is a problem
`SendSMSService` URL-encodes only the static prefix from configuration, then concatenates the decrypted password directly into the `SMSMessage` query parameter and sends it with `HttpClient.GetAsync`. Because the secret is placed in the URL, it is far more likely to leak through reverse-proxy logs, browser history, monitoring tools, upstream access logs, and third-party SMS gateway diagnostics. In addition, special characters in generated passwords (`&`, `#`, `+`, `%`, etc.) can break query parsing and truncate or corrupt the secret delivered to the gateway.

### Evidence
The decrypted password is injected into the URL without encoding and transmitted via GET:

```csharp
string encodedMessage = HttpUtility.UrlEncode(smsMessage);
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
...
HttpResponseMessage response = await client.GetAsync(url);
```

### Recommended fix
Avoid sending secrets in the URL. Use a POST request with the message in the request body, and URL-encode or otherwise safely serialize the full message payload including the password if SMS transmission of passwords is still required.
