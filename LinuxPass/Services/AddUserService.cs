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

        private static readonly Regex UnixUsernameRegex = new("^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.Compiled);
        private static bool IsValidUnixUsername(string username) => UnixUsernameRegex.IsMatch(username);
        private static string EscapeForSingleQuotedShell(string value) => value.Replace("'", "'\"'\"'");
        public string AddUser(string hostname, string sshuser, string privateKeyPath,string username, string password)
        {
            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    client.Connect();

                    if (!IsValidUnixUsername(username))
                    {
                        throw new ArgumentException("Invalid Unix username.", nameof(username));
                    }

                    // Add user remote permissions
                    var escapedUsernamePassword = EscapeForSingleQuotedShell($"{username}:{password}");
                    var command = client.CreateCommand($"sudo useradd -m {username} && printf '%s\\n' '{escapedUsernamePassword}' | sudo chpasswd");
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
    }
}

