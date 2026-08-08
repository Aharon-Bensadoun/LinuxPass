# Code Review Findings

## 1. Password rotation is triggered by GET without CSRF protection
- **Severity:** High
- **Confidence:** High

### Where
- `LinuxPass/Controllers/ServersController.cs:208`
- `LinuxPass/Views/Servers/Index.cshtml:70`

### Summary
The password rotation workflow is exposed as a GET endpoint and is invoked from a normal anchor link. Visiting the URL performs a state-changing action on the target server and stores newly generated credentials, but there is no anti-forgery validation.

### Evidence
`ServersController.Rotate` is defined without `[HttpPost]` or `[ValidateAntiForgeryToken]`:

```csharp
public async Task<IActionResult> Rotate(int id)
{
    var server = await _context.Servers.FindAsync(id);
    string sshKey = _configuration["SSHKeyPath"] ?? "";
    if (server != null)
    {
        var servers = await _context.Servers.ToListAsync();
        var resetPassService = new ResetPassService(_context, _configuration);
        string result = await resetPassService.ResetPass(server.HostSrvName, server.HostSrvUsername, sshKey);
```

The UI triggers it via a simple link:

```html
<a asp-action="Rotate" asp-route-id="@item.Id"
   class="btn btn-outline-success btn-sm">
    <i class="bi bi-arrow-clockwise me-1"></i>Rotate
</a>
```

`ResetPassService.ResetPass` connects over SSH, changes account passwords with `sudo chpasswd`, and inserts the new encrypted passwords into the database.

### Impact
Any website can cause an authenticated user’s browser to request `/Servers/Rotate/{id}` via a link, image, iframe, redirect, or scriptless navigation trick. That silently rotates passwords on the managed server and invalidates the previous credentials. This is a classic CSRF condition made worse by the fact that the action is operationally destructive and affects production access.

### Recommendation
Make `Rotate` a POST-only action protected by `[ValidateAntiForgeryToken]`, and invoke it from a form submission rather than an anchor tag. For especially sensitive operations like rotating server credentials, consider an explicit confirmation step and stronger authorization checks.

---

## 2. Decrypted passwords are rendered directly into the HTML response
- **Severity:** Medium
- **Confidence:** High

### Where
- `LinuxPass/Controllers/PasswordsController.cs:68-76`
- `LinuxPass/Views/Passwords/Details.cshtml:57`
- `LinuxPass/Models/PasswordDetailsViewModel.cs:8`

### Summary
The password details page decrypts the stored password server-side and embeds the plaintext value directly in the rendered HTML. Although the field is initially shown as `<input type="password">`, the secret is still present in the DOM and response body in clear text.

### Evidence
The controller decrypts the password and passes it to the view model:

```csharp
string decryptedpass = CryptorService.Cryptor.DecryptString(encryptedPassword, encryptionKey);
var passwordDetails = new PasswordDetailsViewModel
{
    Id = password.Id,
    Username = password.Username,
    Servername = password.Servername,
    DecryptedPassword = decryptedpass
};
```

The view renders that value directly into the HTML attribute:

```html
<input type="password" class="form-control" value="@Model.DecryptedPassword" id="passwordField" readonly />
```

### Impact
Anyone with access to the page can recover the secret from browser developer tools, the DOM, page source snapshots, accessibility tooling, browser extensions, session recording products, or screenshots. Using `type="password"` only masks the UI; it does not protect the secret once it has been delivered to the client. This increases the blast radius of any endpoint or session compromise and weakens the benefit of storing passwords encrypted at rest.

### Recommendation
Do not include decrypted passwords in the initial HTML response. Gate retrieval behind a deliberate privileged action and return the secret only when strictly necessary, ideally with tighter authorization, auditing, short-lived reveal flows, and controls to reduce caching or accidental reuse.
