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
                try
                {
                    if (!IsValidUnixUsername(username))
                    {
                        throw new ArgumentException("Invalid Unix username.", nameof(username));
                    }

                    string escapedUsername = EscapeShellArgument(username);
                    string escapedPubkey = EscapeShellArgument(File.ReadAllText(_configuration["SSHKeyPath"] ?? ""));

                    client.Connect();
                    // Add user remote permissions
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && printf '%s\\n' {escapedUsername}\\ ALL=\\(ALL\\)\\ NOPASSWD:ALL | sudo EDITOR='tee -a' visudo && printf '%s\\n' {escapedUsername}\\ ALL=\\(ALL:ALL\\)\\ ALL | sudo tee /etc/sudoers.d/{escapedUsername} > /dev/null");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    //Add trusted pubkey to user
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && printf '%s\n' {escapedPubkey} >> ~/.ssh/test");
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

        private static bool IsValidUnixUsername(string username)
        {
            return !string.IsNullOrWhiteSpace(username) && Regex.IsMatch(username, "^[a-z_][a-z0-9_-]{0,14}$", RegexOptions.CultureInvariant);
        }

        private static string EscapeShellArgument(string value)
        {
            return $"'{value.Replace("'", "'\\''")}'";
        }
    }
}
