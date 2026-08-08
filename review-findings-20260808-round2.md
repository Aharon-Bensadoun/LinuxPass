# Code review findings — round 2

## 1. Any authenticated user can decrypt and exfiltrate every managed password
- Severity: high
- Confidence: high

### Evidence
`PasswordsController.Details` decrypts the stored credential for any requested `id` and returns it directly to the view, with no ownership, role, or object-level authorization check:

```csharp
var password = await _context.Passwords
    .FirstOrDefaultAsync(m => m.Id == id);
...
string decryptedpass = CryptorService.Cryptor.DecryptString(encryptedPassword, encryptionKey);
...
return View(passwordDetails);
```

`PasswordsController.SendSMS` likewise accepts any password record `id`, decrypts the secret server-side, and sends it to an arbitrary phone number supplied by the caller:

```csharp
var password = await _context.Passwords.FirstOrDefaultAsync(m => m.Id == id);
...
decryptedPassword = CryptorService.Cryptor.DecryptString(password.EncryptedPassword, _configuration["EncryptionKey"] ?? "");
...
string result = await sendSMSService.SendSMSAsync(smsPhone, decryptedPassword);
```

The UI exposes both capabilities to every authenticated user. The details page renders the plaintext password into the HTML and offers an SMS form that posts only the record ID and destination number:

```html
<input type="password" class="form-control" value="@Model.DecryptedPassword" id="passwordField" readonly />
...
<form method="post" asp-action="SendSMS" ...>
    <input type="hidden" name="id" value="@Model.Id" />
```

Because the application configures only a blanket `RequireAuthenticatedUser()` policy in `Program.cs`, there is no finer-grained authorization layer protecting these actions.

### Impact
Any signed-in user of the web app can iterate IDs, view plaintext credentials for unrelated servers/accounts, and forward them to arbitrary phone numbers. This is a complete confidentiality break for the password vault.

### Remediation
Add object-level authorization before decrypting or sending any secret, restrict these actions to a tightly scoped admin role, and remove the ability to exfiltrate secrets to arbitrary destinations unless there is a strong audited business requirement.

## 2. Server admin password is bound back into the edit form and persisted in plaintext
- Severity: high
- Confidence: high

### Evidence
The `Server` entity includes a `HostSrvPassword` property:

```csharp
public string? HostSrvPassword { get; set; }
```

`ServersController.Edit` loads the `Server` entity from the database and returns it directly to the Razor view:

```csharp
var server = await _context.Servers.FindAsync(id);
...
return View(server);
```

The edit view binds an `<input asp-for="HostSrvPassword" ...>` to that model property:

```html
<input asp-for="HostSrvPassword" type="password" class="form-control"
       placeholder="Enter password" />
```

On a GET request, ASP.NET tag helpers populate `asp-for` from `Model.HostSrvPassword`. If this field is present in the backing table, the application will emit the stored administrative password into the page markup for any authenticated user who can open `/Servers/Edit/{id}`. On POST, the controller also updates the whole bound entity (`_context.Update(server);`), so the same plaintext secret is treated as ordinary persisted model data rather than ephemeral credential input.

### Impact
Administrative server credentials are at risk of plaintext storage and disclosure through the web UI. Even if the current database happens not to persist this column, the code path is fragile: adding the column or scaffolding migrations later would immediately turn the edit page into a secret disclosure endpoint.

### Remediation
Do not store remote host passwords in the `Server` entity. Use a dedicated view model for ephemeral credential entry, mark any transient secret field as non-persisted, and never rehydrate previously submitted admin passwords back into a view.
