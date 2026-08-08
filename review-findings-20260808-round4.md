# Code review findings — round 4

## 1. CSRF-able password rotation endpoint uses GET for a state-changing operation
- **Severity:** high
- **Location:** `LinuxPass/Controllers/ServersController.cs:208`
- **Why this is a problem:** `Rotate(int id)` changes passwords on a remote server and writes new credentials into the database, but it is exposed as a plain GET action with no `[HttpPost]` nor `[ValidateAntiForgeryToken]`. Any page visited by an authenticated user can trigger this endpoint through an image/link/request forgery, causing unintended credential rotation on production hosts.
- **Evidence:** the action calls `ResetPassService.ResetPass(...)`, which SSHes into the target host, executes `sudo chpasswd` for every discovered user, and persists the new encrypted passwords (`LinuxPass/Services/ResetPassService.cs:24-55`).
- **Recommended fix:** require POST for `Rotate`, add anti-forgery validation, and ideally require an explicit confirmation UI before executing remote password changes.

## 2. Stored passwords are encrypted deterministically with a zero IV
- **Severity:** high
- **Location:** `LinuxPass/Services/CryptorService.cs:14-16` and `:35-37`
- **Why this is a problem:** the AES key is derived by truncating/padding the configured string directly, and the IV is hard-coded to 16 zero bytes for every encryption. This makes encryption deterministic: the same plaintext always produces the same ciphertext. Anyone with database access can identify password reuse and perform offline analysis more easily. Reusing a fixed IV with AES-CBC also breaks semantic security expectations.
- **Evidence:** `EncryptString` and `DecryptString` both set `aesAlg.IV = new byte[16]` instead of generating and storing a random IV per record.
- **Recommended fix:** derive a proper key with a KDF, generate a fresh random IV for every encryption, store it alongside the ciphertext, and prefer an authenticated encryption mode such as AES-GCM.

## 3. Password rotation records new credentials even when the remote command fails
- **Severity:** high
- **Location:** `LinuxPass/Services/ResetPassService.cs:39-55`
- **Why this is a problem:** inside the loop, the code executes `sudo chpasswd` and immediately inserts the newly generated password into the database without checking whether the SSH command actually succeeded. SSH.NET exposes command exit status and stderr, but neither is validated here. If `sudo` prompts, the command fails, or password rotation is rejected for one account, LinuxPass will still persist a password that was never applied on the server, effectively desynchronizing the credential vault from reality.
- **Evidence:** `var resetpassresult = command.Execute();` is assigned but ignored, and the code saves `newpassword` unconditionally afterwards.
- **Recommended fix:** check `command.ExitStatus` and `command.Error`, abort on failure, and only persist the new password after the remote change is confirmed. Consider wrapping the whole rotation in a transaction or otherwise marking partial failures explicitly.
