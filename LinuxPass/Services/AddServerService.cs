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
                    ShellCommandSafety.ValidateUnixUsername(username, nameof(username));

                    client.Connect();
                    // Add user remote permissions
                    string escapedSudoersLine = ShellCommandSafety.EscapeSingleQuotedShellArgument($"{username} ALL=(ALL) NOPASSWD:ALL");
                    string escapedSudoersFileLine = ShellCommandSafety.EscapeSingleQuotedShellArgument($"{username} ALL=(ALL:ALL) ALL");

                    var command = client.CreateCommand(
                        $"sudo cp /etc/sudoers /etc/sudoers.bak && " +
                        $"printf '%s\n' '{escapedSudoersLine}' | sudo EDITOR='tee -a' visudo && " +
                        $"printf '%s\n' '{escapedSudoersFileLine}' | sudo tee /etc/sudoers.d/{username}");

                    command.Execute();
                    string result = "Success";
                    if (command.ExitStatus != 0)
                    {
                        throw new Exception($"Error executing command: {command.Error}");
                    }
                    //Add trusted pubkey to user
                    string pubkeypath = _configuration["SSHKeyPath"] ?? "";
                    string pubkey = File.ReadAllText(pubkeypath);
                    string escapedPubkey = ShellCommandSafety.EscapeSingleQuotedShellArgument(pubkey);
                    var pubkeycommand = client.CreateCommand(
                        $"mkdir -p ~/.ssh && printf '%s\n' '{escapedPubkey}' >> ~/.ssh/test");
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
