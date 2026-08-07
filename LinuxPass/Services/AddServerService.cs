using LinuxPass.Data;
using System.Text.RegularExpressions;
using Renci.SshNet;

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
                try
                {
                    if (!Regex.IsMatch(username, "^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.IgnoreCase))
                    {
                        throw new ArgumentException("Invalid username format.", nameof(username));
                    }

                    client.Connect();
                    // Add user remote permissions
                    string escapedUsername = EscapeShellSingleQuotedValue(username);
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{escapedUsername} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{escapedUsername} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{escapedUsername}");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }

                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && echo '{pubkey}' | cat >> ~/.ssh/test");
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

        private static string EscapeShellSingleQuotedValue(string value)
        {
            return value.Replace("'", "'\"'\"'");
        }
    }
}
