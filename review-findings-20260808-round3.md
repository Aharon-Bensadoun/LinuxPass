# Code review findings — 2026-08-08 round 3

## Finding 1: Stored passwords are encrypted with a fixed all-zero IV
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Services/CryptorService.cs` derives the AES key directly from configuration and then uses a constant IV of 16 zero bytes for every encryption and decryption:

```csharp
 aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
 aesAlg.IV = new byte[16]; // Initialization vector with zeros
```

This occurs in both `EncryptString` and `DecryptString`.

### Why this is a problem
Using a fixed IV makes AES encryption deterministic for identical plaintexts under the same key. In this application, passwords are stored in `Passwords.EncryptedPassword`, so two equal generated passwords will always produce the same ciphertext. This leaks equality information across records and weakens confidentiality guarantees for the password vault.

Because the same static IV is also reused forever, compromise of the database gives an attacker more structure to analyze than a scheme with a fresh random IV per record.

### Recommendation
Generate a fresh random IV for each encryption, prepend or store it alongside the ciphertext, and use an authenticated encryption format such as AES-GCM where possible. Also derive the key with a proper KDF or require a binary key of the correct size rather than truncating/padding arbitrary text.

---

## Finding 2: Generated account passwords use `System.Random` instead of a cryptographically secure RNG
- Severity: high
- Confidence: high

### Evidence
`LinuxPass/Services/PassGenService.cs` uses a process-global `Random` instance to generate passwords:

```csharp
private static readonly Random random = new Random();
...
password.Append(characterSet[random.Next(characterSet.Length)]);
```

Those generated values are used as real account passwords in `PasswordsController.Create`:

```csharp
string generatedpass = PassGenService.GeneratePassword(12, PassGenService.Complexity.Low);
...
string result = addUserService.AddUser(password.Servername, sshUser.HostSrvUsername, sshKeypath, password.Username, generatedpass);
```

### Why this is a problem
`System.Random` is not suitable for generating secrets. Its outputs are predictable enough for an attacker who can observe or approximate state/timing, and it does not provide the entropy expected for account credentials.

This is especially risky here because the generated password is immediately provisioned on remote Linux accounts and then stored for later retrieval. A weak generator directly lowers the security of every managed account.

### Recommendation
Use `RandomNumberGenerator` from `System.Security.Cryptography` to generate passwords. Also enforce a stronger default complexity than `Low` for newly provisioned accounts.

---

## Finding 3: The application returns full exception details to authenticated users
- Severity: medium
- Confidence: high

### Evidence
`LinuxPass/Controllers/PasswordsController.cs` catches all exceptions during password decryption and returns the entire exception object in the HTTP response:

```csharp
catch (Exception ex)
{
    return Problem($"error: {ex}");
}
```

### Why this is a problem
Returning raw exception data to end users can disclose stack traces, internal class names, cryptographic failures, configuration mistakes, and environment-specific details. Even if the app requires authentication, any authenticated user who can trigger the failure gains debugging information that should stay server-side.

This is particularly sensitive in a password-management workflow, because failures may reveal clues about encryption keys, record contents, or operational setup.

### Recommendation
Log the detailed exception on the server and return a generic error message to the client. Prefer centralized exception handling for unexpected failures.
