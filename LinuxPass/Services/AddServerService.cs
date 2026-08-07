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
                    var escapedUsername = ShellEscape(username);
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && printf '%s\n' {ShellEscape($"{username} ALL=(ALL) NOPASSWD:ALL")} | sudo EDITOR='tee -a' visudo && printf '%s\n' {ShellEscape($"{username} ALL=(ALL:ALL) ALL")} | sudo tee /etc/sudoers.d/{escapedUsername}");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }

                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && printf '%s\n' {ShellEscape(pubkey)} >> ~/.ssh/test");
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
            return !string.IsNullOrWhiteSpace(username)
                   && username.Length <= 32
                   && Regex.IsMatch(username, "^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant);
        }

        private static string ShellEscape(string value) =>
            $"'{(value ?? string.Empty).Replace("'", "'\\''")}'";
    }
}
