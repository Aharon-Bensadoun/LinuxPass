# Code review findings follow-up 3

## 1. Passwords are sent in the SMS provider URL query string
- **Severity:** High
- **Location:** `LinuxPass/Services/SendSMSService.cs:25`
- **Description:** `SendSMSAsync` appends the decrypted password directly into the URL query string: `...?SMSMessage={encodedMessage}{decryptedPassword}&...`. Query strings are routinely captured by reverse proxies, application gateways, load balancers, browser history, outbound monitoring, and third-party provider logs. Even when TLS is used, this still leaks the cleartext password to every intermediary that records the full request URI.
- **Impact:** Every SMS transmission can permanently disclose the managed account password outside the application boundary. Anyone with access to HTTP access logs or provider request logs can recover passwords for Linux accounts managed by the application.
- **Why this is exploitable:** The controller always decrypts the stored password and passes it to `SendSMSAsync` before making the outbound request (`LinuxPass/Controllers/PasswordsController.cs:180-193`). The service then places that secret into the URL instead of a protected request body.
- **Remediation:** Do not transmit secrets in query strings. Use a POST request with the password in the request body only if the provider explicitly requires receiving the secret, and minimize logging on both client and provider sides. Prefer sending a reset link or one-time code instead of the actual password.

## 2. Detailed exception data is returned to authenticated users from the password details page
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:71`
- **Description:** `Details` catches any exception and returns `Problem($"error: {ex}")`. Interpolating the exception object exposes the full exception text to the HTTP response, which commonly includes stack traces, inner exceptions, cryptographic errors, configuration issues, and file paths.
- **Impact:** Any authenticated user who can trigger a decryption or configuration failure can obtain internal diagnostic details that help with targeted attacks, secret discovery, or environment reconnaissance.
- **Why this is exploitable:** The endpoint is reachable by any authenticated user due to the global authorization policy in `Program.cs`. If decryption fails because of malformed ciphertext, key/configuration drift, or a runtime issue, the application reflects the raw exception content back to the requester instead of logging it server-side.
- **Remediation:** Log the exception internally and return a generic user-facing error message. Avoid including exception text, stack traces, or environment details in HTTP responses.
