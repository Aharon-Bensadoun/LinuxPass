# Code Review Findings

## 1. Any authenticated user can read and exfiltrate every stored password
- Severity: high
- Files: `LinuxPass/Controllers/PasswordsController.cs:50`, `LinuxPass/Controllers/PasswordsController.cs:172`, `LinuxPass/Views/Passwords/Details.cshtml:77`

### Why this is a problem
The application only enforces `RequireAuthenticatedUser()` globally in `Program.cs`, so every signed-in Entra ID user can access password records. `PasswordsController.Details` decrypts and returns any password by numeric `id`, and `SendSMS` will also decrypt the same secret and send it to an arbitrary phone number supplied in the POST body. There is no ownership check, role/policy check, or per-server authorization gate before exposing or transmitting secrets.

In practice, any authenticated user who can guess or enumerate IDs can retrieve credentials for unrelated servers and forward them outside the system.

### Evidence
- `Program.cs:17-20` applies only a global authenticated-user policy.
- `PasswordsController.cs:57-76` fetches a password by `Id` and decrypts it without any authorization decision beyond authentication.
- `PasswordsController.cs:172-195` accepts an arbitrary `smsPhone`, decrypts the password server-side, and sends it externally.
- `Views/Passwords/Details.cshtml:77-78` posts only the password `id`, so access is effectively controlled just by knowledge of that identifier.

### Recommended fix
Add an explicit authorization model for secrets, for example:
- restrict password-management actions to an admin/security role or group, and/or
- associate password/server records with allowed users/groups and enforce that in every read/send/delete/create action.

At minimum, `Details`, `SendSMS`, `Delete`, `Create`, and the index listing should all perform the same server-side authorization check before returning decrypted data or acting on a secret.

## 2. Decrypted passwords are sent in the SMS request query string without URL-encoding
- Severity: high
- File: `LinuxPass/Services/SendSMSService.cs:22-32`

### Why this is a problem
`SendSMSService` URL-encodes the static message prefix, but appends the raw decrypted password directly into the `SMSMessage` query parameter. Generated passwords include special characters, so characters like `&`, `+`, `=` and `#` can break the query string or alter parameter parsing. Because the password is placed in the URL, it is also much more likely to be logged by reverse proxies, gateways, application telemetry, or the SMS provider itself.

This can lead to corrupted SMS content, parameter injection, and additional password disclosure through logs.

### Evidence
- `SendSMSService.cs:22` encodes only `smsMessage`.
- `SendSMSService.cs:25` builds `...?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone=...`, inserting the decrypted secret verbatim into the URL.

### Recommended fix
Do not place secrets in a GET query string. Prefer a POST request with a form or JSON body over HTTPS. If the provider only supports query parameters, URL-encode the entire message including the password and evaluate whether SMS delivery of reusable passwords is acceptable at all.

## 3. Internal exception details are returned to end users
- Severity: medium
- File: `LinuxPass/Controllers/PasswordsController.cs:78-80`

### Why this is a problem
When decryption or any other logic in `Details` fails, the controller returns `Problem($"error: {ex}")`. Serializing the full exception to the HTTP response can expose implementation details such as stack traces, cryptography errors, configuration issues, and data-layer information. Those details help attackers understand internals and can leak sensitive operational context.

### Evidence
- `PasswordsController.cs:78-80` returns the full exception object in the response body.

### Recommended fix
Log the exception server-side and return a generic user-facing error such as `Problem("Unable to load password details.")` or a dedicated error view. Apply the same pattern anywhere else user input or secret handling can fail.

## 4. HSTS is disabled in non-development environments
- Severity: medium
- File: `LinuxPass/Program.cs:28-32`

### Why this is a problem
The app redirects HTTP to HTTPS, but the production pipeline has `app.UseHsts()` commented out. Without HSTS, browsers may still initiate future requests over plain HTTP first, leaving users exposed to SSL stripping or downgrade attempts on hostile networks.

### Evidence
- `Program.cs:28-32` enters the non-development branch but leaves `app.UseHsts()` disabled.

### Recommended fix
Enable `app.UseHsts()` in production unless there is a documented deployment constraint preventing it. If needed, configure the HSTS options explicitly rather than disabling the header entirely.
