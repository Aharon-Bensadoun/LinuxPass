# Code Review Findings Follow-up 6

## 1. Passwords are sent in the SMS provider URL query string
- **Severity:** High
- **Location:** `LinuxPass/Services/SendSMSService.cs:22`
- **Why this is a problem:** `SendSMSAsync` appends `decryptedPassword` directly into the request URL and then sends it with `HttpClient.GetAsync(url)`. That exposes plaintext credentials in application logs, reverse-proxy logs, browser/network tooling, and third-party provider access logs. The password is also concatenated after only URL-encoding the static message prefix, so reserved characters inside the password can corrupt the query string and change the provider request semantics.
- **Evidence:** The URL is built as:
  - `string encodedMessage = HttpUtility.UrlEncode(smsMessage);`
  - `string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&...";`
  - `HttpResponseMessage response = await client.GetAsync(url);`
- **Recommended fix:** Do not place secrets in query strings. Submit SMS payloads in the request body over HTTPS, or better, avoid transmitting passwords over SMS entirely. If this flow must remain, encode the full composed message and move to a POST body handled by the provider SDK/API.

## 2. Server password rotation is triggerable through a GET request
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/ServersController.cs:208`, `LinuxPass/Views/Servers/Index.cshtml:70`
- **Why this is a problem:** `Rotate(int id)` changes remote server passwords and writes new encrypted passwords to the database, but it is exposed as a plain GET action and linked from the index page with `<a asp-action="Rotate" ...>`. That makes a state-changing operation callable by simple navigation, prefetchers, crawlers, copied links, and cross-site request forgery primitives such as image/link loading. Since the app globally requires authentication, an authenticated victim only needs to visit a malicious page to rotate passwords unintentionally.
- **Evidence:**
  - Controller action has no `[HttpPost]` or anti-forgery validation.
  - UI invokes it through an anchor element rather than a protected form post.
- **Recommended fix:** Make rotation a POST-only endpoint protected by `[ValidateAntiForgeryToken]`, invoke it from a form button, and consider an explicit confirmation step because the action is operationally destructive.

## 3. Remote shell command injection via unsanitized username in user creation
- **Severity:** High
- **Location:** `LinuxPass/Services/AddUserService.cs:25`
- **Why this is a problem:** `AddUser` interpolates `username` and `password` directly into a shell command executed over SSH:
  - `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
  The `username` value comes from the MVC model bound in `PasswordsController.Create` and is not constrained to a safe Linux account-name character set server-side. An attacker with application access can submit shell metacharacters (for example `user; command`) and execute arbitrary commands on the managed server with the privileges of the SSH account/sudo configuration.
- **Evidence:**
  - `PasswordsController.Create` accepts `[Bind("Id,Username,Servername,EncryptedPassword,AddTime")] Password password`.
  - `Password.Username` only has `[StringLength(15)]`; there is no regex or allowlist validation.
  - `AddUserService` inserts `username` into the remote shell command without escaping.
- **Recommended fix:** Validate usernames against a strict allowlist compatible with Linux account names before any SSH call, and avoid shell string interpolation entirely where possible. If shell execution is unavoidable, use robust escaping for every untrusted argument and separate command arguments from data instead of composing a single shell line.
