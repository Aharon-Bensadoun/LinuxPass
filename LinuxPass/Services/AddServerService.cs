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
                    client.Connect();
                    EnsureValidUnixUsername(username);
                    // Add user remote permissions
                    var escapedUsername = EscapeShellArgument(username);
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo {EscapeShellArgument($"{username} ALL=(ALL) NOPASSWD:ALL")} | sudo EDITOR='tee -a' visudo && echo {EscapeShellArgument($"{username} ALL=(ALL:ALL) ALL")} | sudo tee /etc/sudoers.d/{escapedUsername}");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }

                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var escapedPubkey = EscapeShellArgument(pubkey);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && printf %s {escapedPubkey} >> ~/.ssh/test");
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
            if (string.IsNullOrWhiteSpace(username) || !Regex.IsMatch(username, "^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant))
            {
                throw new ArgumentException("Invalid Unix username.", nameof(username));
            }
        }

        private static string EscapeShellArgument(string value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            return $"'{value.Replace("'", "'\"'\"'")}'";
        }
    }
}
