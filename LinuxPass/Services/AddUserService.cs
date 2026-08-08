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
        public string AddUser(string hostname, string sshuser, string privateKeyPath,string username, string password)
        {
            username = ShellCommandHelper.ValidateUnixUsername(username, nameof(username));
            var escapedUsername = ShellCommandHelper.EscapeSingleQuoted(username);
            var escapedPassword = ShellCommandHelper.EscapeSingleQuoted(password);

            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var command = client.CreateCommand($"sudo useradd -m {username} && echo '{escapedUsername}:{escapedPassword}' | sudo chpasswd");
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

