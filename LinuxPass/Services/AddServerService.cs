using LinuxPass.Data;
using Renci.SshNet;
using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    public class AddServerService
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;

        public AddServerService(LinuxPassMngContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        public string ResetPass(string hostname, string username, string password)
        {
            using (var client = new SshClient(hostname, username, password))
            {
                EnsureValidUnixUsername(username);

                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var escapedUsername = EscapeSingleQuotedShellArgument(username);
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && printf '%s\n' '{escapedUsername} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && printf '%s\n' '{escapedUsername} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{escapedUsername}");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    // Add trusted public key to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && printf '%s\n' '{EscapeSingleQuotedShellArgument(pubkey)}' >> ~/.ssh/test");
                    pubkeycommand.Execute();
                    if (pubkeycommand.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {pubkeycommand.Error}");
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
