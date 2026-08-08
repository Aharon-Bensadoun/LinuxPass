# Security review findings — round 13

## Finding 1: Detailed exceptions are returned directly to authenticated users
- Severity: Medium
- CWE: CWE-209 (Generation of Error Message Containing Sensitive Information)

### Evidence
`PasswordsController.Details` catches every exception raised while decrypting a password and returns the full exception object to the client:

```csharp
catch (Exception ex)
{
    return Problem($"error: {ex}");
}
```

Because `ex.ToString()` includes exception type names, messages, and stack traces, any authenticated user who can trigger a decryption/configuration failure receives internal implementation details in the HTTP response.

### Impact
This leaks operational details such as missing configuration keys, cryptographic failures, file paths, and code locations. Those details materially lower the cost of follow-on attacks and reveal internals that should stay server-side.

### Recommendation
Log the exception on the server and return a generic error message to the user instead of embedding exception details in the response body.

### Affected file
- `LinuxPass/Controllers/PasswordsController.cs:80`

---

## Finding 2: Password reset command is vulnerable to shell injection through usernames read from the server
- Severity: High
- CWE: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

### Evidence
`ResetPassService.ResetPass` enumerates usernames from `/etc/passwd`, then interpolates each username and generated password into a shell command executed over SSH:

```csharp
foreach (string user in resultArray)
{
    var password = PassGenService.GeneratePassword(12, PassGenService.Complexity.High);
    var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
    var resetpassresult = command.Execute();
    ...
}
```

The username is not shell-escaped before being placed inside single quotes. A local account name containing a single quote or shell metacharacters can break out of the quoted context and inject arbitrary shell syntax into the remote command. Since the command is piped into `sudo chpasswd`, exploitation can reach privileged execution on the managed host.

### Impact
Any attacker able to create or influence a qualifying local username on a managed server can potentially execute arbitrary commands as the SSH automation account and, depending on sudo policy, as root during password rotation.

### Recommendation
Do not build shell commands with string interpolation for account data. Pass data through a safer channel instead, for example by writing `username:password` to standard input of a non-shell process or by strictly escaping shell arguments before command construction.

### Affected file
- `LinuxPass/Services/ResetPassService.cs:39`
