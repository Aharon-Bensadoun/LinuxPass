# Code review follow-up findings (batch 2)

## Finding 1: Server and user names are interpolated directly into privileged SSH commands
- Severity: high
- Confidence: high

### Evidence
`AddUserService.AddUser` builds a shell command by concatenating attacker-controlled `username` and generated `password` directly into a sudo command:

```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```

`username` comes from the HTTP POST body in `PasswordsController.Create`:

```csharp
public async Task<IActionResult> Create([Bind("Id,Username,Servername,EncryptedPassword,AddTime")] Password password)
```

and is rendered from a plain text field in `Views/Passwords/Create.cshtml`.

`AddServerService.ResetPass` does the same with `HostSrvUsername` while granting sudo privileges and writing to `/etc/sudoers.d`:

```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
```

`HostSrvUsername` is bound from `ServersController.Create/Edit` and comes from a plain text field in `Views/Servers/Create.cshtml`.

### Impact
Any authenticated user who can create a password or register/edit a server can inject shell metacharacters into these fields and execute arbitrary commands on managed hosts as the privileged SSH account. In the server-registration path this also allows corruption of sudoers configuration and arbitrary file writes under `/etc/sudoers.d/`.

### Recommendation
Never interpolate request data into shell strings. Use strict allowlists for account names/hostnames, quote arguments safely, and prefer APIs or commands that accept structured arguments instead of shell concatenation.

## Finding 2: Password rotation duplicates credentials indefinitely instead of replacing old secrets
- Severity: medium
- Confidence: high

### Evidence
`ServersController.Rotate` calls `ResetPassService.ResetPass` for every eligible account on the host:

```csharp
string result = await resetPassService.ResetPass(server.HostSrvName, server.HostSrvUsername, sshKey);
```

Inside `ResetPassService.ResetPass`, every rotation inserts a brand new `Password` row:

```csharp
var newpassword = new Password
{
    Username = user,
    Servername = hostname,
    EncryptedPassword = encryptedPassword,
    AddTime = DateTime.Now
};
_context.Add(newpassword);
await _context.SaveChangesAsync();
```

There is no lookup or replacement of the existing `(Username, Servername)` record.

### Impact
Each rotation keeps all previous passwords in the database. Anyone with database access, backup access, or application-level read access to old rows can recover historical credentials for managed accounts long after rotation, defeating the main purpose of rotating passwords.

### Recommendation
Update the current credential record in place (or securely retire old values) instead of appending a new row for the same account/server pair. Add a uniqueness constraint for `(Username, Servername)` if historical versions are not required.

## Finding 3: SMS password delivery leaks credentials in the outbound URL query string
- Severity: high
- Confidence: high

### Evidence
`SendSMSService.SendSMSAsync` appends the decrypted password to the GET query string sent to the external SMS gateway:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

The static message prefix is URL-encoded, but `decryptedPassword` is concatenated afterward without encoding and is transported in the URL itself.

### Impact
The full plaintext password can be exposed through reverse proxies, HTTP client logs, monitoring systems, browser/server diagnostics, and the SMS provider's access logs because URLs are routinely captured. Special characters in the password can also break parameter parsing or inject additional query parameters.

### Recommendation
Do not send secrets in URLs. Use a POST request with a body, encode every user-controlled value, and avoid transmitting plaintext passwords to third-party gateways where possible.
