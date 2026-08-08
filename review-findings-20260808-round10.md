# Code Review Findings — Round 10

## Finding 1 — Password generator uses predictable, low-entropy output for new server accounts
**Severity:** High
**Location:** `LinuxPass/Controllers/PasswordsController.cs:98`, `LinuxPass/Services/PassGenService.cs:7-39`

### Why this is a problem
New server accounts are created with `PassGenService.GeneratePassword(12, PassGenService.Complexity.Low)`. The `Low` mode only draws from lowercase letters, and the generator is backed by a process-wide `System.Random` instance.

`System.Random` is not a cryptographically secure RNG, and the low-complexity alphabet reduces the search space even further. Because these passwords are provisioned onto remote Linux accounts, predictable generation materially lowers the cost of offline guessing and any attack path that exposes one or more generated passwords.

### Recommendation
Use a cryptographically secure generator such as `RandomNumberGenerator.GetInt32`, and generate account passwords from a stronger character set by default. Ideally also guarantee policy requirements explicitly rather than relying on random sampling alone.

---

## Finding 2 — SSH command injection is possible through unsanitized username/password interpolation
**Severity:** Critical
**Location:** `LinuxPass/Services/AddUserService.cs:25`

### Why this is a problem
`AddUserService` builds a shell command with direct string interpolation:

```csharp
$"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd"
```

Both `username` and `password` are inserted into a command line executed on the remote host. The password is currently generated internally, but the username originates from request data in `PasswordsController.Create`. If the username contains shell metacharacters, whitespace, command substitution, quotes, or option prefixes, the remote shell can interpret attacker-controlled content.

Because the command is run via `sudo`, successful injection can become arbitrary privileged command execution on the managed server.

### Recommendation
Do not compose privileged shell commands from untrusted input. Strictly validate usernames against the target platform's allowed account-name pattern before use, and avoid invoking a shell when possible. If shell execution is unavoidable, pass data via safe channels and escape each argument with a well-tested routine appropriate for the remote shell.

---

## Finding 3 — Reversible password encryption uses a static zero IV, making ciphertext deterministic
**Severity:** High
**Location:** `LinuxPass/Services/CryptorService.cs:14-16`, `LinuxPass/Services/CryptorService.cs:35-37`

### Why this is a problem
The encryption routine derives the AES key by truncating/padding configuration text and then sets `aesAlg.IV = new byte[16]` for every encryption and decryption. With a fixed all-zero IV, encrypting the same plaintext under the same key produces the same ciphertext every time.

This leaks equality information between stored passwords and removes an important security property expected from CBC-style encryption with a random IV. It also makes the scheme brittle for future extension and easier to analyze if the database is exposed.

### Recommendation
Generate a fresh random IV for every encryption operation, store it alongside the ciphertext, and authenticate the encrypted payload. Prefer a modern authenticated-encryption construction such as AES-GCM, or store IV + ciphertext + authentication tag in a versioned format.

---

## Finding 4 — Password is sent to the SMS gateway in the URL query string
**Severity:** High
**Location:** `LinuxPass/Services/SendSMSService.cs:25`, `LinuxPass/Services/SendSMSService.cs:32`

### Why this is a problem
The SMS gateway request includes the decrypted password directly in the query string:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&...";
HttpResponseMessage response = await client.GetAsync(url);
```

Query strings are frequently logged by reverse proxies, application monitoring, browser history, intermediary infrastructure, and third-party providers. This design therefore propagates the secret to multiple systems beyond the application boundary. Additionally, `decryptedPassword` itself is not URL-encoded before concatenation, which can corrupt the request or allow parameter injection if the generated alphabet is ever expanded.

### Recommendation
Do not transmit secrets in URLs. Use an HTTPS POST request with the sensitive message in the request body, and encode each field separately through a proper form or JSON serializer. Reassess whether sending account passwords over SMS is acceptable at all, since SMS is not a secure secret-delivery channel.

---

## Finding 5 — Detailed exception objects are returned to clients
**Severity:** Medium
**Location:** `LinuxPass/Controllers/PasswordsController.cs:78-80`

### Why this is a problem
On decryption failure, the controller returns:

```csharp
return Problem($"error: {ex}");
```

Serializing the full exception into the HTTP response can expose stack traces, internal types, configuration-dependent messages, and cryptographic failure details to any authenticated user. That information helps attackers refine exploitation attempts and increases the impact of otherwise routine failures.

### Recommendation
Return a generic user-facing error message and log the full exception server-side through the application's logging pipeline. Avoid disclosing exception internals in HTTP responses outside controlled development diagnostics.
