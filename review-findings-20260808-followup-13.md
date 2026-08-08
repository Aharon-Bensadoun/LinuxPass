# Code Review Findings — Follow-up 13

## Scope
- Repository: `Aharon-Bensadoun/LinuxPass`
- Goal: identify **new** review findings without repeating the previous follow-up.

## Findings

### 1. Critical — Password rotation and deletion are exposed as GET actions without CSRF protection
- **Files:** `LinuxPass/Controllers/ServersController.cs:182`, `LinuxPass/Controllers/PasswordsController.cs:137`
- **What happens:**
  - `ServersController.Rotate(int id)` performs a state-changing operation that rotates passwords on a remote server, but it is callable through a simple GET request and has no `[ValidateAntiForgeryToken]` protection.
  - The UI triggers it with a plain anchor in `LinuxPass/Views/Servers/Index.cshtml`, so a malicious page can force an authenticated user’s browser to invoke password rotation just by loading an image/link.
  - The delete workflow also starts from a GET endpoint that reveals whether an object exists and presents a destructive action page directly from a bookmarkable URL.
- **Why it matters:** Any authenticated user who visits an attacker-controlled page can be tricked into rotating passwords on managed servers. This is a classic CSRF issue on a high-impact administrative action.
- **Recommendation:** Restrict state-changing actions to POST only, add `[ValidateAntiForgeryToken]`, and replace the rotate link with a form submit button.

### 2. High — Decrypted credentials are sent in the SMS provider URL query string
- **Files:** `LinuxPass/Services/SendSMSService.cs:23`, `LinuxPass/Controllers/PasswordsController.cs:172`
- **What happens:** `SendSMSAsync` builds a GET URL containing the decrypted password in the `SMSMessage` query parameter and sends it with `HttpClient.GetAsync(url)`.
- **Why it matters:** Query strings are commonly logged by reverse proxies, web servers, APM tools, browser history, and the SMS gateway itself. This leaks plaintext credentials outside the application boundary even when TLS is enabled.
- **Recommendation:** Do not place secrets in URLs. Use a POST request with the payload in the body, avoid sending plaintext passwords over SMS if possible, and ensure downstream logging redacts sensitive fields.

### 3. Medium — The app configures Microsoft Identity but never maps Razor Pages, risking broken auth/account endpoints
- **Files:** `LinuxPass/Program.cs:11-21`, `LinuxPass/Program.cs:38-41`
- **What happens:** The app registers `AddDefaultIdentity(...)` and `AddMicrosoftIdentityWebAppAuthentication(...)`, but the pipeline only calls `MapControllerRoute(...)`. There is no `AddRazorPages()` registration and no `MapRazorPages()`.
- **Why it matters:** ASP.NET Core Identity UI and Microsoft Identity UI rely on Razor Pages endpoints for login/logout/account flows. If those endpoints are not mapped, authentication/account routes may 404 or fail unpredictably, undermining the global authorization policy and making recovery/admin workflows brittle.
- **Recommendation:** Register Razor Pages (`builder.Services.AddRazorPages()`) and map them (`app.MapRazorPages()`), or remove the unused UI/auth stack and keep a single coherent authentication approach.

### 4. Medium — Exceptions are returned verbatim to end users, exposing internal details
- **Files:** `LinuxPass/Controllers/PasswordsController.cs:77`
- **What happens:** The `Details` action catches any exception and returns `Problem($"error: {ex}")`, which serializes the full exception object into the HTTP response.
- **Why it matters:** This can disclose stack traces, cryptographic/decryption failure details, configuration mistakes, and code structure to authenticated users. Such information materially helps follow-on attacks and weakens defense-in-depth.
- **Recommendation:** Log the exception server-side and return a generic error message to the client.
