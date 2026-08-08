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
            using (var client = new SshClient(hostname, sshuser, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    var validatedUsername = ShellCommandHelper.ValidateUnixUsername(username);
                    var escapedUsername = ShellCommandHelper.EscapeSingleQuotedValue(validatedUsername);
                    var escapedPassword = ShellCommandHelper.EscapeSingleQuotedValue(password);

                    client.Connect();
                    // Add user remote permissions
                    var command = client.CreateCommand($"sudo useradd -m '{escapedUsername}' && echo '{escapedUsername}:{escapedPassword}' | sudo chpasswd");
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

