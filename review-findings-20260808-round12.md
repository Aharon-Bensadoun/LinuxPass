# Code Review Findings — Round 12

## High — Password is sent in the SMS provider URL query string
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:172-195`, `LinuxPass/Services/SendSMSService.cs:14-32`
- **What happens:** `SendSMS` decrypts the stored password and passes it to `SendSMSAsync`, which appends the plaintext password directly into the request URL as part of `SMSMessage`. Because the provider call is made with `HttpClient.GetAsync(url)`, the secret is exposed in places that routinely log or retain URLs: reverse proxies, web server access logs, browser/network tooling, APM traces, and the downstream SMS gateway itself.
- **Why this matters:** Anyone with access to request logs or monitoring for the application or SMS provider can recover live server passwords without needing the database encryption key.
- **Recommendation:** Do not place passwords in query strings. If SMS delivery of secrets is still required, send the content in a POST body over HTTPS and avoid logging the body. Prefer one-time retrieval flows or out-of-band secret sharing instead of transmitting reusable passwords over SMS.

## High — Password rotation is a state-changing GET endpoint without anti-CSRF protection
- **Location:** `LinuxPass/Controllers/ServersController.cs:208-228`
- **What happens:** `Rotate(int id)` performs a full password rotation on a server, writes the new passwords to the database, and returns results, but it is exposed as a GET action with no `[HttpPost]` and no `[ValidateAntiForgeryToken]`.
- **Why this matters:** Any authenticated user can be induced to trigger rotations by visiting a page containing an auto-loaded image/link to `/Servers/Rotate/{id}`. Because this action changes credentials on remote servers, a CSRF attack can cause operational disruption and unexpected credential churn without the victim intending it.
- **Recommendation:** Make rotation a POST-only action protected with an anti-forgery token, and require an explicit confirmation UI before executing the rotation.
