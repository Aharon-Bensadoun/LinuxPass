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
            username = ShellCommandSafety.ValidateUnixUserName(username);

            using (var client = new SshClient(hostname, username, password))
            {
                try
                {
                    client.Connect();
                    // Add user remote permissions
                    var escapedSudoersLine = ShellCommandSafety.EscapeSingleQuoted($"{username} ALL=(ALL) NOPASSWD:ALL");
                    var escapedSudoersFileLine = ShellCommandSafety.EscapeSingleQuoted($"{username} ALL=(ALL:ALL) ALL");
                    var command = client.CreateCommand(
                        $"sudo cp /etc/sudoers /etc/sudoers.bak && " +
                        $"printf '%s\\n' '{escapedSudoersLine}' | sudo EDITOR='tee -a' visudo && " +
                        $"printf '%s\\n' '{escapedSudoersFileLine}' | sudo tee /etc/sudoers.d/{username} > /dev/null");
                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    // Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    var escapedPubkey = ShellCommandSafety.EscapeSingleQuoted(pubkey.Trim());
                    var pubkeycommand = client.CreateCommand(
                        $"umask 077 && mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && " +
                        $"printf '%s\\n' '{escapedPubkey}' | cat >> ~/.ssh/authorized_keys && " +
                        $"chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys");
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
