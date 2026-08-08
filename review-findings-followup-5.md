# Follow-up Code Review Findings 5

## 1. Password reset can be triggered with a cross-site GET request
- **Severity:** high
- **Location:** `LinuxPass/Controllers/ServersController.cs:185`, `LinuxPass/Views/Servers/Index.cshtml:63`
- **Issue:** The `Rotate` action changes server state by rotating the password, but it is exposed as a plain GET endpoint and linked from the index view with a normal anchor tag. Because the application relies on cookie-based authentication, any external page can cause a logged-in operator's browser to request `/Servers/Rotate/{id}` and trigger a password rotation without the operator's intent.
- **Impact:** A CSRF or even a browser prefetch/crawler hit can unexpectedly rotate privileged server credentials, causing operational outages and desynchronizing stored credentials.
- **Recommendation:** Make `Rotate` a POST-only action protected with `[ValidateAntiForgeryToken]`, and submit it from a form instead of a link.

## 2. SMS endpoint is missing anti-forgery protection
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:172`, `LinuxPass/Views/Passwords/Details.cshtml:76`
- **Issue:** `SendSMS` is a POST action but it does not use `[ValidateAntiForgeryToken]`. The details view renders a normal authenticated form that posts directly to this endpoint.
- **Impact:** A malicious site can forge a POST from the victim's browser and force the application to send decrypted passwords to an attacker-controlled phone number, turning the authenticated user's session into a password exfiltration primitive.
- **Recommendation:** Add `[ValidateAntiForgeryToken]` to `SendSMS` and include the anti-forgery token in the form.

## 3. Decrypted passwords are sent in the SMS provider URL query string
- **Severity:** high
- **Location:** `LinuxPass/Services/SendSMSService.cs:24-31`
- **Issue:** `SendSMSAsync` appends `decryptedPassword` directly into the request URL and sends it with `HttpClient.GetAsync(url)`. Query strings are routinely logged by reverse proxies, application performance monitoring, web server access logs, and upstream providers. The password is also concatenated after encoding only the static message template, so the secret itself is not URL-encoded before being placed in the URI.
- **Impact:** Every SMS delivery leaks the decrypted password to multiple logging and observability layers outside the application's control. Special characters in the password can also corrupt the request or alter how the SMS gateway parses it.
- **Recommendation:** Do not transmit secrets in the query string. Use an HTTPS POST body supported by the SMS API, URL-encode each field separately, and avoid returning or logging provider errors that may include sensitive request details.

## 4. Password details page links to a non-existent edit action
- **Severity:** medium
- **Location:** `LinuxPass/Views/Passwords/Details.cshtml:14`, `LinuxPass/Controllers/PasswordsController.cs`
- **Issue:** The password details page renders an `asp-action="Edit"` link, but `PasswordsController` has no `Edit` GET or POST action. Clicking the button routes to `/Passwords/Edit/{id}`, which returns 404.
- **Impact:** Operators are presented with a workflow that cannot succeed. In practice this breaks credential maintenance from the UI and can lead users to assume a password was editable when it is not.
- **Recommendation:** Either implement the missing edit flow or remove the button from the view.
