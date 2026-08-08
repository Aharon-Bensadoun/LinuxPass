# Code review follow-up 5

## Finding 1: Any authenticated page POST can trigger SMS sends because SendSMS lacks anti-forgery protection
- Severity: medium
- Confidence: high
- Location: `LinuxPass/Controllers/PasswordsController.cs:170-195`, `LinuxPass/Views/Passwords/Details.cshtml:74-94`

### Why this matters
`PasswordsController.SendSMS` is a state-changing POST endpoint that sends the decrypted password to an arbitrary phone number, but it is missing `[ValidateAntiForgeryToken]`. The corresponding Razor form also does not render an anti-forgery token explicitly. A malicious site can trick a logged-in operator’s browser into POSTing to `/Passwords/SendSMS`, causing password exfiltration by SMS without the operator intending to do so.

### Evidence
The action is declared only with `[HttpPost]`:

```csharp
// POST: SMS/SendSMS
[HttpPost]
public async Task<IActionResult> SendSMS(string smsPhone, int id, string decryptedPassword)
```

And the form posts directly to that action:

```html
<form method="post" asp-action="SendSMS" class="needs-validation" novalidate>
    <input type="hidden" name="id" value="@Model.Id" />
    ...
</form>
```

### Suggested fix
Require anti-forgery validation on `SendSMS` and include the anti-forgery token in the form (or rely on the FormTagHelper only after verifying it is active in this view). Also consider restricting the action to authorized roles because it reveals and distributes secrets.

## Finding 2: Failed password rotation still persists new passwords because SSH command errors are ignored
- Severity: high
- Confidence: high
- Location: `LinuxPass/Services/ResetPassService.cs:24-56`

### Why this matters
`ResetPassService.ResetPass` loops through users, generates and stores a new encrypted password for each one, but never checks `command.ExitStatus` or `command.Error` after `chpasswd` runs. If `sudo chpasswd` fails for one or more users, the method still inserts the generated password into the database and eventually returns `"Success"`. That leaves LinuxPass showing credentials that were never actually applied on the target host, which can lock operators out during an incident.

### Evidence
The code executes the password reset command and immediately writes the generated password to the database:

```csharp
var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
...
var resetpassresult = command.Execute();
...
var newpassword = new Password
{
    Username = user,
    Servername = hostname,
    EncryptedPassword = encryptedPassword,
    AddTime = DateTime.Now
};
_context.Add(newpassword);
await _context.SaveChangesAsync();
```

No validation of `command.ExitStatus` happens anywhere in the loop.

### Suggested fix
Check the SSH command result before saving anything, and fail the whole rotation if any account update fails. Wrapping the database inserts in a transaction would also prevent partial rotations from being committed.

## Finding 3: Adding a server can corrupt the operator’s authorized keys by appending the public key to `~/.ssh/test`
- Severity: medium
- Confidence: medium
- Location: `LinuxPass/Services/AddServerService.cs:31-33`

### Why this matters
The onboarding flow is supposed to install the management public key so future SSH key-based operations work, but it writes the key to `~/.ssh/test` instead of `~/.ssh/authorized_keys`. As a result, the configured key is never authorized for login. On servers where password auth is later disabled, LinuxPass can lose management access entirely.

### Evidence
The code reads the configured key and appends it to a file named `test`:

```csharp
string pubkey = File.ReadAllText(pubkeypath);
var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && echo '{pubkey}' | cat >> ~/.ssh/test");
pubkeycommand.Execute();
```

Nothing updates `authorized_keys` or file permissions.

### Suggested fix
Append the key to `~/.ssh/authorized_keys` (or the target user’s home directory explicitly), deduplicate existing entries, and set secure permissions on both the directory and file.
