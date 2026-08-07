using LinuxPass.Data;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Renci.SshNet;

namespace LinuxPass.Services
{
    public class AddUserService
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;

        public AddUserService(LinuxPassMngContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        private static readonly Regex UnixUsernameRegex = new("^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant);

        public string AddUser(string hostname, string sshuser, string privateKeyPath, string username, string password)
        {
            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    if (!UnixUsernameRegex.IsMatch(username))
                    {
                        return "Username must be a valid Unix account name.";
                    }

                    client.Connect();
                    // Add user remote permissions
                    string escapedUsername = EscapeShellSingleQuotedArgument(username);
                    string escapedPassword = EscapeShellSingleQuotedArgument(password);
                    var command = client.CreateCommand($"sudo useradd -m -- '{escapedUsername}' && printf '%s:%s\\n' '{escapedUsername}' '{escapedPassword}' | sudo chpasswd");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    client.Disconnect();
                    return (result);
                }
                catch (Exception ex)
                {
                    return (ex.Message);
                }
            }
        }

        private static string EscapeShellSingleQuotedArgument(string value)
        {
            return value.Replace("'", "'\\''");
        }
    }
}

