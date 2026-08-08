# Code review findings — 2026-08-08 run 2

## Finding 1 — Stored passwords are encrypted with a deterministic, effectively low-entropy key setup
- Severity: high
- Confidence: high

### Why this matters
`CryptorService` encrypts every password with AES using a zero IV and derives the AES key by padding/truncating the configured `EncryptionKey` to 32 UTF-8 bytes. This makes encryption deterministic for identical plaintexts and also silently accepts weak or empty configuration values. In practice, two identical passwords produce identical ciphertexts, and a missing/short key degrades to a predictable padded key instead of failing closed.

Because this application is explicitly a password-management system, deterministic reversible encryption materially increases impact if the database is exposed.

### Evidence
`LinuxPass/Services/CryptorService.cs`
```csharp
aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
aesAlg.IV = new byte[16]; // Initialization vector with zeros
```

Call sites accept an empty key fallback instead of rejecting startup/runtime:
- `LinuxPass/Controllers/PasswordsController.cs`
- `LinuxPass/Services/ResetPassService.cs`

Examples:
```csharp
string encryptionKey = _configuration["EncryptionKey"] ?? "";
```

### Recommended fix
- Fail startup when `EncryptionKey` is missing or too weak.
- Use authenticated encryption with a random nonce/IV per record.
- Store the nonce alongside ciphertext.
- Prefer a proper KDF or a purpose-built secret store rather than manual pad/truncate key handling.

---

## Finding 2 — SSH commands interpolate untrusted usernames/passwords directly into shell commands
- Severity: high
- Confidence: high

### Why this matters
Multiple services construct remote shell commands with string interpolation using data that ultimately comes from HTTP form input (`Username`, `HostSrvUsername`, generated/reset passwords, server names/user lists). Any quote, shell metacharacter, command substitution, or newline in these values can break the intended command and execute attacker-controlled shell fragments on the managed Linux hosts.

This is particularly dangerous because the commands are run with `sudo` and include account creation and password reset operations.

### Evidence
`LinuxPass/Services/AddUserService.cs`
```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```

`LinuxPass/Services/AddServerService.cs`
```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
```

`LinuxPass/Services/ResetPassService.cs`
```csharp
var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
```

### Recommended fix
- Never concatenate shell commands with untrusted values.
- Strictly validate usernames/server-side to a safe allowlist (for example Linux username syntax).
- Pass data through safe escaping routines or, better, avoid shell parsing entirely when possible.
- Treat generated passwords as untrusted for shell purposes too, because random generators can emit shell-significant characters.

---

## Finding 3 — Deleting a password record does not remove or disable the remote account
- Severity: medium
- Confidence: high

### Why this matters
`PasswordsController.DeleteConfirmed` removes only the local database row. The Linux user created earlier remains active on the remote host with its last assigned password. Operators can reasonably assume that deleting the entry revokes access, but in reality it only deletes the audit/lookup record and leaves the credential valid on the server.

That creates a dangerous mismatch between the UI state and the real security state of managed hosts.

### Evidence
`LinuxPass/Controllers/PasswordsController.cs`
```csharp
[HttpPost, ActionName("Delete")]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteConfirmed(int id)
{
    var password = await _context.Passwords.FindAsync(id);
    if (password != null)
    {
        _context.Passwords.Remove(password);
    }

    await _context.SaveChangesAsync();
    return RedirectToAction(nameof(Index));
}
```

No corresponding SSH call is made to delete, lock, or rotate the remote account before removing the record.

### Recommended fix
- Either make deletion revoke the remote account (`userdel`, lock, or rotate to an unknown secret) before removing the record,
- or rename/reframe the feature so it is clearly only deleting local history/metadata.
- Consider transactional/error-handling semantics so the DB row is not removed when remote revocation fails.
