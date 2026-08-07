using LinuxPass.Data;
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
            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    client.Connect();
                    EnsureValidUnixUsername(username);
                    // Add user remote permissions
                    var escapedCredentials = EscapeShellArgument($"{username}:{password}");
                    var command = client.CreateCommand($"sudo useradd -m {EscapeShellArgument(username)} && echo {escapedCredentials} | sudo chpasswd");
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

