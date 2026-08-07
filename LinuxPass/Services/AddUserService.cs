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

        public string AddUser(string hostname, string sshuser, string privateKeyPath, string username, string password)
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
                    var command = client.CreateCommand($"sudo useradd -m -- {ShellEscape(username)} && printf '%s\n' {ShellEscape($"{username}:{password}")} | sudo chpasswd");
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
            return !string.IsNullOrWhiteSpace(username)
                   && username.Length <= 32
                   && Regex.IsMatch(username, "^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant);
        }

        private static string ShellEscape(string value) =>
            $"'{(value ?? string.Empty).Replace("'", "'\\''")}'";
    }
}

