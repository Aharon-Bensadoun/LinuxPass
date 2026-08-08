# Code review findings — batch 6

## 1. Password generation uses predictable `System.Random`
- **Severity:** High
- **Location:** `LinuxPass/Services/PassGenService.cs:7-34`
- **Why it matters:** `PassGenService.GeneratePassword` relies on a process-wide `System.Random` instance to generate credentials that are later provisioned on remote hosts (`PasswordsController.Create`, `ResetPassService.ResetPass`). `System.Random` is not a cryptographically secure PRNG and its output can be predicted from a small amount of observed state or timing information. That makes generated passwords substantially weaker than intended.
- **Evidence:**
  - `private static readonly Random random = new Random();`
  - `password.Append(characterSet[random.Next(characterSet.Length)]);`
- **Recommendation:** Replace `System.Random` with a cryptographically secure generator such as `RandomNumberGenerator.GetInt32(...)`, and consider enforcing character-class guarantees instead of only sampling from a combined alphabet.

## 2. Password rotation is triggered by a GET request
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:208-228`, `LinuxPass/Views/Servers/Index.cshtml:64-67`
- **Why it matters:** `Rotate` resets passwords for all eligible users on a server, which is a high-impact state-changing operation. Exposing it as a GET action makes it reachable via links, prefetchers, crawlers, or embedded images, and it bypasses the anti-forgery protections already used on the POST actions. An authenticated user can therefore be tricked into rotating credentials simply by visiting an attacker-controlled page.
- **Evidence:**
  - Controller action has no `[HttpPost]` or `[ValidateAntiForgeryToken]` and performs the reset directly.
  - The view invokes it through an anchor tag: `<a asp-action="Rotate" asp-route-id="@item.Id" ...>`
- **Recommendation:** Convert `Rotate` to a POST-only action protected by `[ValidateAntiForgeryToken]`, and invoke it through a form submission rather than a link.

## 3. `SendSMS` lacks anti-forgery protection for a sensitive action
- **Severity:** Medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:171-193`, `LinuxPass/Views/Passwords/Details.cshtml:75-92`
- **Why it matters:** `SendSMS` decrypts the stored password and transmits it to an arbitrary phone number supplied by the request. Although the endpoint is POST-only, it is not decorated with `[ValidateAntiForgeryToken]`, unlike the other form handlers in the application. A cross-site form post from another origin could therefore cause an authenticated user’s session to send credentials to an attacker-controlled number.
- **Evidence:**
  - Controller action: `[HttpPost] public async Task<IActionResult> SendSMS(...)`
  - Form exists in the details view, but there is no anti-forgery validation on the action.
- **Recommendation:** Add `[ValidateAntiForgeryToken]` to `SendSMS` and keep the form-generated anti-forgery token in the Razor view. Consider additionally restricting which destinations can receive passwords, or removing SMS transmission of passwords entirely.

## 4. SSH commands interpolate untrusted input directly into shell commands
- **Severity:** Critical
- **Location:** `LinuxPass/Services/AddUserService.cs:20-27`, `LinuxPass/Services/AddServerService.cs:20-36`, `LinuxPass/Services/ResetPassService.cs:36-44`
- **Why it matters:** Several services build shell commands by concatenating attacker-controlled values such as usernames, passwords, and public key contents into single-quoted shell strings. If a value contains shell metacharacters or quote characters, it can break out of the intended command and execute arbitrary commands on the managed Linux hosts with elevated privileges (`sudo`).
- **Evidence:**
  - `"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd"`
  - `"... echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo ..."`
  - `"mkdir -p ~/.ssh && echo '{pubkey}' | cat >> ~/.ssh/test"`
  - `"echo '{user}:{password}' | sudo chpasswd"`
- **Recommendation:** Do not build privileged shell commands by string interpolation. Validate usernames against a strict allowlist, escape or reject unsafe characters, and prefer safer mechanisms such as SFTP file upload plus fixed shell scripts, or command arguments that never pass through a shell.
