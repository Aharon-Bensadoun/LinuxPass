# Code Review Findings

## Finding 1: User-controlled server/user names are interpolated into privileged SSH shell commands

**Severity:** High
**Confidence:** High

### Summary
Several services build shell commands by directly interpolating controller-supplied values such as usernames and host-related fields into command strings executed over SSH with elevated privileges. A user who can submit crafted values through the web UI can inject shell metacharacters and execute arbitrary commands on the managed Linux hosts.

### Evidence
`PasswordsController.Create` takes `password.Username` and `password.Servername` from the POST body and forwards them to `AddUserService.AddUser`:

```csharp
string result = addUserService.AddUser(password.Servername, sshUser.HostSrvUsername, sshKeypath, password.Username, generatedpass);
```

`AddUserService` then embeds the attacker-controlled `username` directly in a shell command:

```csharp
var command = client.CreateCommand($"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd");
```

Likewise, `ServersController.Create/Edit` forward user-controlled `HostSrvUsername` to `AddServerService.ResetPass`, which builds privileged commands with the raw value:

```csharp
var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{username} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{username} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username}");
```

Because these values are inserted without validation or shell escaping, inputs containing shell metacharacters (for example `bob; curl ... #`) will alter the executed command.

### Impact
Any authenticated user of the application can reach these forms and can cause arbitrary command execution on target Linux servers using the application’s SSH credentials. This can lead to full compromise of managed hosts, persistence via sudoers modifications, lateral movement, and credential theft.

### Recommendation
Do not construct shell commands via string interpolation for user-controlled values. Strictly validate usernames/hostnames against a safe allowlist (for example POSIX username syntax), and pass arguments through a safe execution mechanism that avoids invoking a shell. If shell execution is unavoidable, quote/escape each argument with a proven shell-escaping routine and reject characters outside the expected character set.

## Finding 2: Password encryption uses a fixed all-zero IV, making ciphertext deterministic

**Severity:** Medium
**Confidence:** High

### Summary
`CryptorService` encrypts all passwords with AES using a constant IV of sixteen zero bytes. Reusing the same IV with the same key makes encryption deterministic, so identical plaintext passwords always produce identical ciphertexts.

### Evidence
Both encryption and decryption hard-code the IV:

```csharp
aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
aesAlg.IV = new byte[16]; // Initialization vector with zeros
```

This means two stored passwords encrypted under the same application key will have the same `EncryptedPassword` value whenever the plaintexts match.

### Impact
An attacker who gains read access to the password table can correlate accounts that share the same password and track password reuse over time without knowing the encryption key. This weakens confidentiality of the stored secrets and materially reduces the work needed for offline analysis after any database leak.

### Recommendation
Use an authenticated encryption scheme with a fresh random nonce/IV per encryption operation, such as AES-GCM or AES-CBC plus HMAC with a random IV stored alongside the ciphertext. Derive the encryption key with a proper KDF and version the ciphertext format so existing records can be migrated safely.
