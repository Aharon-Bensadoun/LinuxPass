using LinuxPass.Data;
using Renci.SshNet;
using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    public class AddServerService
    {
        private static readonly Regex UnixUsernameRegex = new("^[a-z_][a-z0-9_-]{0,31}$", RegexOptions.Compiled);
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;

        public AddServerService(LinuxPassMngContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        public string ResetPass(string hostname, string username, string password)
        {
            if (!IsValidUnixUsername(username))
            {
                return "Invalid Unix username.";
            }

            using (var client = new SshClient(hostname, username, password))
            {
                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var escapedUsername = EscapeShellSingleQuotedString(username);
                    var sudoersNoPasswordLine = EscapeShellSingleQuotedString($"{username} ALL=(ALL) NOPASSWD:ALL");
                    var sudoersAllLine = EscapeShellSingleQuotedString($"{username} ALL=(ALL:ALL) ALL");
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && printf '%s\n' {sudoersNoPasswordLine} | sudo EDITOR='tee -a' visudo && printf '%s\n' {sudoersAllLine} | sudo tee /etc/sudoers.d/{username}");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var escapedPubKey = EscapeShellSingleQuotedString(pubkey);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && printf '%s\n' {escapedPubKey} >> ~/.ssh/test");
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
            return !string.IsNullOrWhiteSpace(username) && UnixUsernameRegex.IsMatch(username);
        }

        private static string EscapeShellSingleQuotedString(string value)
        {
            return $"'{value.Replace("'", "'\\''")}'";
        }
    }
}
