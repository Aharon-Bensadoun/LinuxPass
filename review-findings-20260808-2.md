# Review Findings — 2026-08-08 (Pass 2)

## Finding 1: SendSMS POST endpoint lacks anti-CSRF protection for a sensitive action
- Severity: medium
- Confidence: high

### Evidence
`PasswordsController.SendSMS` is a state-changing POST action that triggers delivery of a decrypted password to an attacker-controlled phone number, but it does not require an anti-forgery token:

```csharp
// POST: SMS/SendSMS
[HttpPost]
public async Task<IActionResult> SendSMS(string smsPhone, int id, string decryptedPassword)
{
    var password = await _context.Passwords.FirstOrDefaultAsync(m => m.Id == id);
    ...
    string result = await sendSMSService.SendSMSAsync(smsPhone, decryptedPassword);
    ViewData["Message"] = result;
    return View("Details", passwordDetails);
}
```

The corresponding form in `Views/Passwords/Details.cshtml` posts to this action without an explicit anti-forgery token either:

```html
<form method="post" asp-action="SendSMS" class="needs-validation" novalidate>
    <input type="hidden" name="id" value="@Model.Id" />
    ...
</form>
```

Other sensitive POST actions in the project use `[ValidateAntiForgeryToken]`, which makes this omission stand out.

### Impact
Any website visited by an authenticated LinuxPass user can forge a cross-site POST to `/Passwords/SendSMS` and cause the application to send the selected account password to an attacker-controlled phone number. Because the controller re-decrypts the password server-side from the supplied `id`, the attacker does not need to know the secret value in advance.

### Recommendation
Require anti-forgery validation on `SendSMS` and include the anti-forgery token in the form. Consider adding a second confirmation step for any workflow that exfiltrates credentials.

---

## Finding 2: SMS integration places the plaintext password in the query string of an outbound GET request
- Severity: high
- Confidence: high

### Evidence
`SendSMSService.SendSMSAsync` appends the decrypted password directly into the URL used for the SMS gateway request and then sends it with `HttpClient.GetAsync`:

```csharp
string encodedMessage = HttpUtility.UrlEncode(smsMessage);
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
...
HttpResponseMessage response = await client.GetAsync(url);
```

The decrypted secret is therefore embedded in the request target instead of being transmitted in a request body.

### Impact
Query strings are commonly logged by reverse proxies, application performance monitoring agents, outbound web proxies, load balancers, and the SMS provider itself. As a result, every SMS delivery can leak the managed account password into multiple logging and observability systems that are outside the application’s intended password storage boundary.

### Recommendation
Do not send secrets in URLs. Use a POST request with a body supported by the SMS provider, and avoid concatenating the password into a generic message template when a one-time retrieval link or out-of-band secret delivery mechanism would suffice.
