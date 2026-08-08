using LinuxPass.Data;
using Renci.SshNet;

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
            username = ShellCommandHelper.ValidateUnixUsername(username, nameof(username));
            var escapedUsername = ShellCommandHelper.EscapeSingleQuoted(username);
            var sudoersLine = ShellCommandHelper.EscapeSingleQuoted($"{username} ALL=(ALL) NOPASSWD:ALL");

            using (var client = new SshClient(hostname, username, password))
            {
                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{sudoersLine}' | sudo EDITOR='tee -a' visudo && printf '%s\n' '{escapedUsername} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/{username} >/dev/null");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && printf '%s\n' '{ShellCommandHelper.EscapeSingleQuoted(pubkey)}' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys");
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
    }
}
