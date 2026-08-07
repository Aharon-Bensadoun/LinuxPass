using LinuxPass.Data;
using Microsoft.EntityFrameworkCore;
using Renci.SshNet;

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

        private static bool IsValidUnixUserName(string username)
        {
            return !string.IsNullOrWhiteSpace(username)
                && username.Length <= 32
                && username.All(c => char.IsLetterOrDigit(c) || c is '-' or '_');
        }

        private static string ShellEscape(string value)
        {
            return $"'{value.Replace("'", "'\\''")}'";
        }
        public string AddUser(string hostname, string sshuser, string privateKeyPath,string username, string password)
        {
            if (!IsValidUnixUserName(username))
            {
                return "Invalid Unix username.";
            }

            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var command = client.CreateCommand(
                        $"sudo useradd -m -- {ShellEscape(username)} && printf '%s\\n' {ShellEscape($"{username}:{password}")} | sudo chpasswd");

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

