# Code review findings — follow-up 4

## 1. Arbitrary password disclosure endpoint can be triggered without validating caller intent
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:166-189`

### Description
`PasswordsController.SendSMS` accepts an `id` from the POST body, ignores the submitted `decryptedPassword`, decrypts the stored password for that record, and immediately sends it through `SendSMSService`.

There is no authorization check beyond the application-wide “authenticated user” policy, no ownership/role validation for the targeted password entry, and no server-side validation that the supplied phone number belongs to an approved recipient. Any authenticated user who can reach this endpoint can therefore submit another password record’s `id` and exfiltrate its plaintext password over SMS to an arbitrary number.

### Impact
This is a direct privilege-escalation / secret-exfiltration path: one low-privilege authenticated user can obtain passwords for unrelated managed accounts and route them to an external phone number.

### Recommendation
Restrict this action to a narrow administrative role/policy, verify that the caller is authorized to access the targeted password entry, and enforce recipient validation on the server side (for example, only pre-approved phone numbers associated with the caller or the managed account). Consider removing SMS delivery of plaintext passwords entirely.

## 2. SSH commands interpolate untrusted values directly into the shell
- **Severity:** high
- **Location:** `LinuxPass/Services/AddUserService.cs:25`, `LinuxPass/Services/AddServerService.cs:24,34`, `LinuxPass/Services/ResetPassService.cs:39`

### Description
Multiple SSH commands are constructed with string interpolation and then executed remotely via `/bin/sh`, for example:
- `sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd`
- `echo '{username} ALL=(ALL) NOPASSWD:ALL' ...`
- `echo '{pubkey}' | cat >> ~/.ssh/test`
- `echo '{user}:{password}' | sudo chpasswd`

The interpolated values originate from database records, controller-bound request data, generated passwords, and key file contents. None of them are shell-escaped or constrained to a safe character set before being embedded in the command text.

### Impact
A crafted username, hostname-related record, or key content containing shell metacharacters or quotes can break out of the intended command and execute arbitrary commands on the managed Linux server with elevated privileges. In practice this can lead to full remote code execution on every host managed by the application.

### Recommendation
Do not compose shell commands with raw interpolation. Prefer APIs/protocols that avoid a shell entirely. If shell execution is unavoidable, strictly validate usernames against a conservative allowlist and escape every interpolated argument with a robust shell-quoting routine before execution.

## 3. Deterministic AES encryption uses a zero IV for every password
- **Severity:** medium
- **Location:** `LinuxPass/Services/CryptorService.cs:10-41`

### Description
`CryptorService.Cryptor` derives the AES key by padding/truncating the configured string and then sets `aesAlg.IV = new byte[16]` for both encryption and decryption. This produces deterministic ciphertext for identical plaintext values under the same key.

### Impact
Equal passwords encrypt to equal database values, which leaks password reuse patterns across users and servers. If an attacker obtains the password table, the deterministic construction materially weakens confidentiality compared with standard randomized authenticated encryption.

### Recommendation
Generate a fresh random IV/nonce for every encryption operation, store it alongside the ciphertext, and use an authenticated encryption scheme (for example AES-GCM) or AES-CBC plus HMAC with independent keys.

## 4. Server deletion leaves managed credentials orphaned and stale
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/ServersController.cs:177-188`

### Description
`ServersController.DeleteConfirmed` deletes only the selected `Server` row. The corresponding `Password` records for accounts on that server are not deleted, invalidated, or otherwise marked stale.

### Impact
The UI and database can continue to expose historical credentials for a server that is no longer managed. Operators may mistakenly treat those entries as live credentials, and any user with access to the application can keep retrieving secrets for decommissioned or reassigned hostnames long after the server record has been removed.

### Recommendation
Define and enforce the intended lifecycle explicitly: either cascade-delete related `Password` records, soft-delete and hide them, or mark them revoked/stale during server removal so they are no longer displayed or disclosed.

## 5. SMS request places plaintext passwords in the query string
- **Severity:** medium
- **Location:** `LinuxPass/Services/SendSMSService.cs:18-31`

### Description
`SendSMSService.SendSMSAsync` appends the decrypted password directly into a GET URL:

```csharp
string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";
```

Because the password is sent as part of the request URI, it is likely to be exposed in application logs, reverse-proxy logs, browser/network tooling, APM traces, and third-party provider request logging.

### Impact
Even when the SMS provider itself is trusted, plaintext credentials are unnecessarily propagated into multiple logging surfaces, multiplying the number of places where a single password can leak.

### Recommendation
Use an HTTPS POST request with the secret placed in the request body, minimize/disable logging of sensitive fields, and avoid transmitting plaintext passwords through third-party messaging services where possible.
