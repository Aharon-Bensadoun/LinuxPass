using LinuxPass.Data;
using Microsoft.EntityFrameworkCore;
using Renci.SshNet;
using System.Text.RegularExpressions;

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
        public string AddUser(string hostname, string sshuser, string privateKeyPath,string username, string password)
        {
            EnsureValidUnixUsername(username);

            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var escapedUsername = EscapeSingleQuotedShellArgument(username);
                    var escapedPassword = EscapeSingleQuotedShellArgument(password);
                    var command = client.CreateCommand($"sudo useradd -m -- '{escapedUsername}' && printf '%s\n' '{escapedUsername}:{escapedPassword}' | sudo chpasswd");
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

        private static void EnsureValidUnixUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username) || !Regex.IsMatch(username, "^[a-z_][a-z0-9_-]*[$]?$"))
            {
                throw new ArgumentException("Invalid Unix username.", nameof(username));
            }
        }

        private static string EscapeSingleQuotedShellArgument(string value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            return value.Replace("'", "'\"'\"'");
        }
    }
}

