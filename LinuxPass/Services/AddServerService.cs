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
                    client.Connect();
                    ShellCommandSafety.ValidateUnixUsername(username);

                    // Add user remote permissions
                    var sudoersEntry = ShellCommandSafety.SingleQuote(username + " ALL=(ALL) NOPASSWD:ALL");
                    var sudoersFileEntry = ShellCommandSafety.SingleQuote(username + " ALL=(ALL:ALL) ALL");
                    var command = client.CreateCommand($"sudo cp /etc/sudoers /etc/sudoers.bak && printf '%s\n' {sudoersEntry} | sudo EDITOR='tee -a' visudo && printf '%s\n' {sudoersFileEntry} | sudo tee /etc/sudoers.d/{username}");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }

                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var escapedPubkey = ShellCommandSafety.SingleQuote(pubkey.Trim());
                    var pubkeycommand = client.CreateCommand($"install -d -m 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && printf '%s\n' {escapedPubkey} >> ~/.ssh/authorized_keys");
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
