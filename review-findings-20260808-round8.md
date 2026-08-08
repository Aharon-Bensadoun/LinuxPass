# Round 8 Code Review Findings

## 1. Password generation is predictable and low entropy
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:98`, `LinuxPass/Services/PassGenService.cs:7-39`
- **Issue:** New server accounts are always created with `PassGenService.GeneratePassword(12, PassGenService.Complexity.Low)`. The `Low` mode only uses lowercase letters, and the generator relies on `System.Random`, which is not cryptographically secure.
- **Impact:** Every generated credential is restricted to 26 characters with a predictable PRNG. Anyone who can approximate generator state or brute-force a 12-character lowercase password gets a dramatically smaller search space than expected for privileged server credentials.
- **Recommendation:** Use a cryptographically secure generator such as `RandomNumberGenerator.GetBytes`, include upper/lower/digits/symbols by default for machine passwords, and enforce per-class character requirements.

## 2. Remote command injection in account provisioning
- **Severity:** critical
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:118-123`, `LinuxPass/Services/AddUserService.cs:25`
- **Issue:** User-controlled `password.Username` is interpolated directly into a shell command:
  ```csharp
  $"sudo useradd -m {username} && echo '{username}:{password}' | sudo chpasswd"
  ```
  The model only limits length to 15 characters; it does not restrict shell metacharacters.
- **Impact:** An authenticated user who can create password entries can inject shell syntax into the SSH command and execute arbitrary commands as the SSH account (typically with sudo in this flow), leading to full compromise of the managed Linux host.
- **Recommendation:** Do not construct shell commands with string interpolation. Strictly validate usernames against an allowlist such as `^[a-z_][a-z0-9_-]*$`, pass arguments without invoking a shell, and avoid piping secrets through shell command strings.

## 3. Stored passwords use deterministic AES without integrity protection
- **Severity:** high
- **Location:** `LinuxPass/Services/CryptorService.cs:12-16`, `LinuxPass/Services/CryptorService.cs:33-37`
- **Issue:** Encryption uses AES with a zero IV for every record and derives the key by truncating/padding the configured string:
  ```csharp
  aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
  aesAlg.IV = new byte[16];
  ```
  There is no per-record random IV/nonce and no authentication tag/MAC.
- **Impact:** Equal plaintext passwords encrypt to equal ciphertexts, leaking password reuse patterns across accounts. Because ciphertexts are unauthenticated, tampering can go undetected and may trigger malleability issues or fault-based abuse.
- **Recommendation:** Replace this with an authenticated encryption scheme (for example AES-GCM) using a fresh random nonce per secret and a proper key-management story. Store nonce + ciphertext + tag per record.

## 4. Decrypted passwords are sent in URL query strings to the SMS gateway
- **Severity:** high
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:180-193`, `LinuxPass/Services/SendSMSService.cs:24-32`
- **Issue:** `SendSMS` decrypts the stored password, then `SendSMSService` appends that plaintext directly into the GET request URL:
  ```csharp
  string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}...";
  HttpResponseMessage response = await client.GetAsync(url);
  ```
  The password portion is not URL-encoded, and even if it were, it still travels in the query string.
- **Impact:** Plaintext credentials can be exposed through reverse proxies, web server logs, APM tooling, browser/network debugging, and third-party gateway logs. Special characters in generated passwords can also corrupt the query string.
- **Recommendation:** Never place secrets in URLs. Use a POST body over TLS to the SMS provider, encode all parameters properly, and reconsider whether sending long-lived passwords over SMS is acceptable at all.

## 5. Sensitive exception details are returned to end users
- **Severity:** medium
- **Location:** `LinuxPass/Controllers/PasswordsController.cs:78-80`
- **Issue:** The `Details` action catches any exception and returns `Problem($"error: {ex}")`, which includes the full exception string in the HTTP response.
- **Impact:** Failures during decryption or data access can leak stack traces, crypto errors, configuration details, and internal code paths to authenticated users, making later exploitation easier.
- **Recommendation:** Log the exception server-side and return a generic error message to the client.

## 6. HSTS is explicitly disabled outside development
- **Severity:** medium
- **Location:** `LinuxPass/Program.cs:28-33`
- **Issue:** Production requests use `UseHttpsRedirection()`, but `UseHsts()` is commented out.
- **Impact:** Clients that first connect over HTTP remain vulnerable to SSL stripping or downgrade attacks on hostile networks because the browser is not instructed to pin HTTPS for future requests.
- **Recommendation:** Re-enable HSTS in non-development environments unless there is a documented deployment reason not to.
