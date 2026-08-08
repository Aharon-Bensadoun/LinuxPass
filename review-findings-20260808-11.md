# Code Review Findings

## [high] Passwords are transmitted in the SMS provider URL query string

- **Location:** `LinuxPass/Services/SendSMSService.cs:25`, `LinuxPass/Services/SendSMSService.cs:32`, `LinuxPass/Controllers/PasswordsController.cs:193`
- **Status:** Confirmed

### Description
`PasswordsController.SendSMS` decrypts the stored account password and passes it to `SendSMSService.SendSMSAsync`. That service then appends the plaintext password directly into the `SMSMessage` query parameter and sends the request with `HttpClient.GetAsync(url)`.

Because the secret is placed in the request URL instead of the request body, the password is exposed to every component that records request URIs: reverse proxies, application telemetry, outbound HTTP logging, network appliances, and the SMS provider itself. Even if TLS is enabled, URLs are commonly logged and retained outside the application boundary.

### Impact
Any operator or system with access to HTTP request logs can recover users' plaintext passwords. This defeats the purpose of encrypting passwords at rest and turns routine observability/logging infrastructure into a credential disclosure channel.

### Evidence
The SMS flow is wired as follows:

1. `PasswordsController.SendSMS` decrypts the password from the database and calls `SendSMSService.SendSMSAsync(smsPhone, decryptedPassword)`.
2. `SendSMSService.SendSMSAsync` builds:
   ```csharp
   string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
   ```
3. The service sends the request with:
   ```csharp
   HttpResponseMessage response = await client.GetAsync(url);
   ```

### Recommendation
Do not place secrets in URLs. Send the SMS request as a `POST` with the message in the request body (for example `application/x-www-form-urlencoded` or JSON, depending on the provider API). Also avoid transmitting passwords over SMS entirely if possible; prefer one-time reset links/codes or temporary credentials with forced rotation on first use.
