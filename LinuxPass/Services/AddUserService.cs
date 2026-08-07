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

        private static readonly Regex ValidUsernameRegex = new Regex("^[a-z_][a-z0-9_-]{0,31}$", RegexOptions.Compiled);

        private static string ShellEscape(string value)
        {
            return $"'{value.Replace("'", "'\\''")}'";
        }

        public string AddUser(string hostname, string sshuser, string privateKeyPath, string username, string password)
        {
            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(username) || !ValidUsernameRegex.IsMatch(username))
                    {
                        return "Invalid username format.";
                    }

                    client.Connect();
                    string escapedUsername = ShellEscape(username);
                    string escapedPasswordEntry = ShellEscape($"{username}:{password}");

                    // Add user remote permissions
                    var command = client.CreateCommand($"sudo useradd -m -- {escapedUsername} && printf %s\\n {escapedPasswordEntry} | sudo chpasswd");
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

