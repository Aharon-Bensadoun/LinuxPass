using LinuxPass.Data;
using Renci.SshNet;
using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    public class AddUserService
    {
        private static readonly Regex UnixUsernameRegex = new("^[a-z_][a-z0-9_-]{0,31}$", RegexOptions.Compiled);
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;

        public AddUserService(LinuxPassMngContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        public string AddUser(string hostname, string sshuser, string privateKeyPath,string username, string password)
        {
            if (!IsValidUnixUsername(username))
            {
                return "Invalid Unix username.";
            }

            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var escapedUsername = EscapeShellSingleQuotedString(username);
                    var escapedPassword = EscapeShellSingleQuotedString(password);
                    var command = client.CreateCommand($"sudo useradd -m -- {escapedUsername} && echo {escapedUsername}:{escapedPassword} | sudo chpasswd");
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

