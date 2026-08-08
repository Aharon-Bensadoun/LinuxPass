# Code review findings

## 1. SMS sending leaks decrypted passwords in the query string
- **Severity:** high
- **Location:** `LinuxPass/Services/SendSMSService.cs:25`
- **Why this is a problem:** `SendSMSAsync` appends the decrypted password directly into the URL of an outbound GET request:
  `...?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone=...`
  Query strings are routinely captured by reverse proxies, web servers, APM tools, browser/network logs, and third-party providers. That means every SMS dispatch exposes the plaintext credential outside the application boundary, even when TLS is enabled.
- **Impact:** any operator or system with access to request logs at the SMS provider or along the network path can recover user passwords. This defeats the point of encrypting them at rest.
- **Recommendation:** do not send secrets in a GET query string. Use a POST request with the message in the request body, and avoid transmitting passwords over SMS entirely if possible.

## 2. Password reset history stores every old password indefinitely
- **Severity:** high
- **Location:** `LinuxPass/Services/ResetPassService.cs:47-53`, `LinuxPass/Controllers/PasswordsController.cs:30-47`
- **Why this is a problem:** each rotation inserts a brand new `Password` row for the same `(Username, Servername)` pair without deleting or superseding the previous row. The UI hides this by grouping on `(Username, Servername)` and only showing the latest entry in `Index`, but the old encrypted passwords remain in the database forever.
- **Impact:** if the application encryption key is ever disclosed, an attacker can decrypt not only current credentials but the full historical backlog of prior passwords for each managed account. The issue is amplified because `Details(int? id)` still allows direct retrieval of any older row by ID.
- **Recommendation:** replace the existing row instead of appending a new one, or explicitly expire and purge prior credentials during rotation. If history is required, protect it with stricter authorization, retention limits, and auditing.

## 3. Decryption exceptions are returned to authenticated users verbatim
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:78-81`
- **Why this is a problem:** `Details` catches any exception raised during decryption and returns `Problem($"error: {ex}")`. That serializes the full exception text back into the HTTP response.
- **Impact:** configuration mistakes, cryptographic failures, provider errors, or unexpected runtime exceptions can leak stack traces, key-handling details, and internal implementation information to any signed-in user who can hit the endpoint.
- **Recommendation:** log the exception server-side and return a generic user-facing error message instead of echoing the exception contents.
