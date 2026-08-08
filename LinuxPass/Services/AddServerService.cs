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
            using (var client = new SshClient(hostname, username, password))
            {
                try
                {
                    var validatedUsername = ShellCommandHelper.ValidateUnixUsername(username);
                    var escapedUsername = ShellCommandHelper.EscapeSingleQuotedValue(validatedUsername);

                    client.Connect();
                    // Add user remote permissions
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && echo '{escapedUsername} ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo && echo '{escapedUsername} ALL=(ALL:ALL) ALL' | sudo tee '/etc/sudoers.d/{escapedUsername}'");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var escapedPubkey = ShellCommandHelper.EscapeSingleQuotedValue(pubkey);
                    var pubkeycommand = client.CreateCommand($"mkdir -p ~/.ssh && echo '{escapedPubkey}' | cat >> ~/.ssh/test");
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
