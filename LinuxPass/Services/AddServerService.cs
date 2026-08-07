using LinuxPass.Data;
using System.Text.RegularExpressions;
using Renci.SshNet;

namespace LinuxPass.Services
{
    public class AddServerService
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;
        private static readonly Regex UnixUsernamePattern =
            new(@"^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant);

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
                    ValidateUnixUsername(username);

                    client.Connect();
                    // Add user remote permissions
                    var escapedUsername = EscapeShellArgument(username);
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && printf '%s\n' {escapedUsername} | sed 's/$/ ALL=(ALL) NOPASSWD:ALL/' | sudo EDITOR='tee -a' visudo && printf '%s\n' {escapedUsername} | sed 's/$/ ALL=(ALL:ALL) ALL/' | sudo tee /etc/sudoers.d/{escapedUsername} >/dev/null");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var escapedPubKey = EscapeShellArgument(pubkey);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && chmod 700 ~/.ssh && printf '%s' {escapedPubKey} >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys");
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

        private static void ValidateUnixUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username) || !UnixUsernamePattern.IsMatch(username))
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

            return $"'{value.Replace("'", "'\\''")}'";
        }
    }
}
