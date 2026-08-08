# Code Review Findings Follow-up 4

## Finding 1: Secret-bearing password reset endpoint is executable via GET and without CSRF protection
- Severity: high
- Confidence: high

### Evidence
`ServersController.Rotate` performs a state-changing password rotation but is exposed as a plain action without `[HttpPost]` or `[ValidateAntiForgeryToken]`:

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

File: `LinuxPass/Controllers/ServersController.cs`

The application configures a global authenticated-user policy, so any logged-in user who loads a malicious page can be induced to hit `/Servers/Rotate?id=...` cross-site. Because this action changes remote credentials and persists the new encrypted password history, executing it over GET makes it CSRFable and also vulnerable to accidental triggering by prefetchers/crawlers.

### Impact
An attacker can silently rotate credentials on managed servers for any authenticated victim, causing unauthorized password changes, denial of service for legitimate users, and unexpected password inventory churn.

### Recommendation
Restrict the action to `POST` only and enforce anti-forgery validation. Trigger it from a form submission rather than a link/GET request.

## Finding 2: SMS sending endpoint lacks anti-forgery protection and can be triggered cross-site
- Severity: medium
- Confidence: high

### Evidence
`PasswordsController.SendSMS` is a POST action but does not validate an anti-forgery token:

```csharp
[HttpPost]
public async Task<IActionResult> SendSMS(string smsPhone, int id, string decryptedPassword)
{
    var password = await _context.Passwords.FirstOrDefaultAsync(m => m.Id == id);
```

File: `LinuxPass/Controllers/PasswordsController.cs`

The corresponding form in `Views/Passwords/Details.cshtml` uses `method="post"`, but without `[ValidateAntiForgeryToken]` on the action the endpoint still accepts cross-site form submissions from arbitrary origins.

### Impact
A malicious site can cause an authenticated user’s browser to submit SMS requests to arbitrary phone numbers, leading to password disclosure over SMS and message abuse/cost exposure.

### Recommendation
Add `[ValidateAntiForgeryToken]` to the action and keep the form-generated anti-forgery token enabled. Consider additional authorization/rate-limiting around outbound SMS.

## Finding 3: The SMS provider request leaks plaintext passwords in the URL query string
- Severity: high
- Confidence: high

### Evidence
`SendSMSService.SendSMSAsync` appends the decrypted password directly into the query string of a GET request:

```csharp
string encodedMessage = HttpUtility.UrlEncode(smsMessage);
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

File: `LinuxPass/Services/SendSMSService.cs`

Only the static prefix message is URL-encoded; the decrypted password is concatenated raw into the URL. Query strings are routinely captured by reverse proxies, web server logs, browser history, outbound monitoring, and third-party observability tooling.

### Impact
Plaintext credentials can be exposed outside the application boundary even when the downstream SMS API itself succeeds, creating credential leakage through logs and intermediaries.

### Recommendation
Do not transmit secrets in a URL. Use a POST request with the full message in the body, encode all user-controlled fields correctly, and avoid including decrypted credentials in any loggable transport metadata.
