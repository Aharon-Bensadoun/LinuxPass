# Code review findings follow-up 3

## 1. Stored passwords use deterministic AES encryption with a zero IV
- **Severity:** High
- **Location:** `LinuxPass/Services/CryptorService.cs:12-35`
- **Why this is a problem:** `EncryptString` derives the AES key directly from the configured string by truncating/padding it and always uses `new byte[16]` as the IV. Because the IV never changes, encrypting the same password twice produces the same ciphertext. Anyone with database access can therefore identify password reuse across users/servers and build frequency analysis over stored secrets. This removes one of the key security properties expected from symmetric encryption at rest.
- **Evidence:** Both `EncryptString` and `DecryptString` set `aesAlg.IV = new byte[16]` and no random nonce/IV is generated, stored, or prepended to the ciphertext.
- **Recommended fix:** Generate a cryptographically random IV for every encryption operation, prepend/store it with the ciphertext, and derive the AES key using a proper KDF. If the application only needs one-way verification, prefer hashing; if it truly needs recovery, use authenticated encryption with per-record randomness.

## 2. Password rotation endpoint is a GET action that performs destructive state changes
- **Severity:** High
- **Location:** `LinuxPass/Controllers/ServersController.cs:208-228`, `LinuxPass/Views/Servers/Index.cshtml:58-61`
- **Why this is a problem:** `Rotate(int id)` resets passwords on the remote server and writes new credentials to the database, but it is exposed as a plain GET action and linked from an `<a>` tag. Any page load, crawler, prefetcher, link scanner, or malicious third-party site can trigger it without a user’s intentional submission or antiforgery protection. This makes credential rotation vulnerable to CSRF and accidental execution.
- **Evidence:** The action has no `[HttpPost]` or `[ValidateAntiForgeryToken]`, and the view triggers it through `<a asp-action="Rotate" asp-route-id="@item.Id">`.
- **Recommended fix:** Change the action to POST-only, require antiforgery validation, and invoke it from a form/button. Consider adding an explicit confirmation step because the action changes remote system state.

## 3. SMS delivery leaks decrypted passwords through the request URL
- **Severity:** High
- **Location:** `LinuxPass/Services/SendSMSService.cs:14-29`
- **Why this is a problem:** The service appends the decrypted password directly into the query string of a GET request. Query strings are routinely logged by reverse proxies, web servers, APM tools, browser/network tooling, and the downstream SMS gateway. This exposes the very secret the application is trying to protect, even if the transport is HTTPS.
- **Evidence:** `url` is built as `...?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone=...`, then sent with `client.GetAsync(url)`.
- **Recommended fix:** Send the payload in the body of a POST request instead of in the URL, and avoid passing raw passwords to third-party services where possible. If SMS must be used, send a one-time link or temporary credential instead of the stored password.
