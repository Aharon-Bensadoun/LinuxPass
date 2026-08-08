# Code Review Findings — 2026-08-08 (Follow-up 9)

## Finding: Decrypted passwords are sent to the SMS provider in the request URL

- Severity: high
- Confidence: high

### Summary
`SendSMSService.SendSMSAsync` appends the decrypted password directly into the query string of an outbound `HttpClient.GetAsync(...)` call. Even when HTTPS is used, query strings are commonly captured by reverse proxies, web server access logs, outbound HTTP telemetry, and third-party provider logs. This causes plaintext credentials to be exposed outside the application boundary.

### Evidence
`PasswordsController.SendSMS` decrypts the stored password and passes it to the SMS service:

```csharp
string result = await sendSMSService.SendSMSAsync(smsPhone, decryptedPassword);
```

`LinuxPass/Services/SendSMSService.cs` then builds a GET URL containing the secret:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
HttpResponseMessage response = await client.GetAsync(url);
```

The `Details` page explicitly exposes this workflow as a normal user action via the `SendSMS` form.

### Impact
Any infrastructure or vendor component that logs request URLs can retain end-user passwords in plaintext. That includes local application diagnostics, reverse proxies, corporate egress monitoring, APM tooling, and the SMS gateway itself. This materially increases credential disclosure risk and undermines the value of encrypting the password at rest.

### Recommendation
Do not transmit decrypted credentials in URLs. Prefer not sending passwords by SMS at all. If the business flow must remain, send the payload in the body of a POST request, confirm the provider contract avoids URL logging, minimize log retention, and consider replacing password disclosure with a one-time reset or retrieval token instead.
