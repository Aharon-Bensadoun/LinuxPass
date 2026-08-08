# Code review findings — follow-up 6

## 1. Password decryption and raw exception text are exposed to any authenticated user
- **Severity:** high
- **Where:** `LinuxPass/Controllers/PasswordsController.cs:45-73`
- **Why it matters:** The application applies a global `RequireAuthenticatedUser()` policy in `Program.cs`, but `PasswordsController.Details` has no resource-level authorization check before decrypting and returning the password. That means any signed-in user who can guess or enumerate an `id` can retrieve another server account's cleartext password. On top of that, the catch block returns `Problem($"error: {ex}")`, which leaks exception details and can expose cryptographic/configuration internals to the browser.
- **How to reproduce:** Sign in as any valid account, request `/Passwords/Details/1`, then increment the id until an existing record is found. The decrypted password is rendered without verifying ownership or role membership. If decryption fails, the full exception text is sent back in the HTTP response body.
- **Suggested fix:** Restrict password disclosure to an explicit privileged role/policy and enforce server-side authorization before decryption. Replace the raw exception response with a generic error message plus structured server-side logging.

## 2. State-changing password rotation is exposed as a GET endpoint with no CSRF protection
- **Severity:** high
- **Where:** `LinuxPass/Controllers/ServersController.cs:181-205`
- **Why it matters:** `ServersController.Rotate(int id)` performs a full password rotation on the target host and writes new encrypted passwords to the database, but it is callable via a plain GET request. Because the app relies on cookie authentication for signed-in users, another site can trigger the operation through a forged `<img>` or link visit. This is a classic CSRF vulnerability on a high-impact admin action.
- **How to reproduce:** While logged into LinuxPass, visit any page controlled by an attacker that embeds `/Servers/Rotate/1` as an image or auto-opened URL. The browser will send the authentication cookie, the action executes, and all eligible accounts on that server are rotated.
- **Suggested fix:** Make rotation a POST-only action, require `[ValidateAntiForgeryToken]`, and trigger it from a form/button instead of a link. Consider adding an explicit confirmation flow because the operation is destructive.

## 3. Password encryption uses a fixed zero IV, making identical passwords trivially correlatable
- **Severity:** medium
- **Where:** `LinuxPass/Services/CryptorService.cs:10-39`
- **Why it matters:** `EncryptString` derives the AES key by truncating/padding the configured string and then always sets `aesAlg.IV = new byte[16]`. With a constant IV, encrypting the same plaintext with the same key always produces the same ciphertext. Anyone with database access can immediately tell when two users or two rotation events share the same password, which defeats semantic security for stored secrets.
- **How to reproduce:** Call `CryptorService.Cryptor.EncryptString("P@ssw0rd!", key)` twice. Both invocations return exactly the same Base64 string because the IV never changes.
- **Suggested fix:** Generate a fresh random IV for every encryption, prepend/store it with the ciphertext, and authenticate the payload (for example with AES-GCM or encrypt-then-MAC). Also validate the configured key length instead of silently padding/truncating it.

## 4. Shell commands interpolate unsanitized usernames/passwords into privileged SSH commands
- **Severity:** high
- **Where:** `LinuxPass/Services/AddUserService.cs:18-23`, `LinuxPass/Services/ResetPassService.cs:34-39`, `LinuxPass/Services/AddServerService.cs:20-34`
- **Why it matters:** Several services build shell command strings with direct interpolation of values that come from the database, HTTP input, generated passwords, or configuration. Examples include `sudo useradd -m {username}`, `echo '{user}:{password}' | sudo chpasswd`, and sudoers file writes containing `{username}`. A crafted username containing shell metacharacters or quotes can break out of the intended command and execute arbitrary commands on the managed Linux server with elevated privileges.
- **How to reproduce:** Submit a username such as `bob; touch /tmp/pwned #` through the create-user flow. The generated command in `AddUserService` becomes `sudo useradd -m bob; touch /tmp/pwned # && ...`, so the injected command runs on the remote server when the SSH call executes.
- **Suggested fix:** Reject usernames that do not match a strict safe pattern for Linux accounts, and stop composing privileged shell commands through string concatenation. Use robust argument escaping at minimum, or better, invoke purpose-built scripts/APIs on the target host that accept validated parameters out-of-band.
