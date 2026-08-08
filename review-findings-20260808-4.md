# Code Review Findings

## Finding 1: Server onboarding stores remote admin passwords in clear text
- Severity: high
- Confidence: high

### Where
- `LinuxPass/Controllers/ServersController.cs:116`
- `LinuxPass/Models/Server.cs:10`
- `LinuxPass/Views/Servers/Edit.cshtml:58`

### Why this matters
`ServersController.Edit` updates the bound `Server` entity directly with `_context.Update(server)`. The bound model includes `HostSrvPassword`, and the `Server` model maps that property to the database. As a result, every server password entered in the create/edit workflow is persisted in the application database in clear text.

Any read access to the database, debug dumps, backups, or accidental admin disclosure exposes reusable SSH credentials for managed servers. Because these are infrastructure passwords, compromise extends beyond the application itself.

### Evidence
The edit action binds `HostSrvPassword` and writes the entity back unchanged:

```csharp
public async Task<IActionResult> Edit(int id, [Bind("Id,HostSrvName,HostSrvUsername,HostSrvPassword,HostSSHKeyPath")] Server server)
{
    ...
    _context.Update(server);
    await _context.SaveChangesAsync();
}
```

The model persists the property:

```csharp
public string? HostSrvPassword { get; set; }
```

The edit view renders a password field, causing operators to resubmit the secret into the persisted entity:

```html
<input asp-for="HostSrvPassword" type="password" class="form-control" placeholder="Enter password" />
```

### Recommendation
Do not persist remote server passwords in the `Server` entity. Use a dedicated view model for transient credential entry, and exclude password fields from EF persistence entirely. If a secret must be retained, store it in a purpose-built secret manager or encrypt it with authenticated encryption and strict key management rather than saving it as plain application data.

## Finding 2: Password SMS delivery leaks secrets in the request URL
- Severity: high
- Confidence: high

### Where
- `LinuxPass/Services/SendSMSService.cs:23`

### Why this matters
`SendSMSService.SendSMSAsync` appends the decrypted password directly into the query string of a GET request to the SMS gateway. Query strings are routinely logged by reverse proxies, application telemetry, browser/network tooling, and third-party providers. That means every transmitted password is likely to be recorded in multiple places outside the intended secret store.

An attacker who gains access to HTTP logs or provider dashboards can recover valid passwords without needing database or application access.

### Evidence
The code constructs a GET URL containing `decryptedPassword` as a query parameter and sends it with `HttpClient.GetAsync`:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

### Recommendation
Do not place secrets in URLs. Send SMS requests via POST with the sensitive message in the request body, and verify the provider/API path avoids logging message content. Reassess whether transmitting passwords over SMS is acceptable at all; an out-of-band reset link or one-time retrieval flow is typically safer.
