using LinuxPass.Data;
using LinuxPass.Models;
using Renci.SshNet;
using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    public class ResetPassService
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;
        private static readonly Regex UnixUsernameRegex = new("^[a-z_][a-z0-9_-]{0,31}$", RegexOptions.Compiled);

        public ResetPassService(LinuxPassMngContext context, IConfiguration configuration)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public async Task<string> ResetPass(string hostname, string username, string privateKeyPath)
        {
            using (var client = new SshClient(hostname, username, new PrivateKeyFile(privateKeyPath)))
            {
                try
                {
                    client.Connect();
                    // List user in the hostname
                    var listuser = client.CreateCommand("for user in $(cut -d: -f1 /etc/passwd); do [ $(id -u $user) -ge 1000 ] && [ $user != 'nobody' ] && [ $user != 'aharonbe' ] && [ $user != 'root' ] && echo $user; done");
                    var userresult = listuser.Execute();
                    string[] resultArray = userresult.Split(new[] { '\n' }, StringSplitOptions.None)
                                                     .Select(line => line.Trim())
                                                     .Where(line => !string.IsNullOrEmpty(line))
                                                     .ToArray();
                    if (resultArray.Length > 0)
                    {
                        foreach (string user in resultArray)
                        {
                            if (!IsValidUnixUsername(user))
                            {
                                continue;
                            }

                            string encryptionKey = _configuration["EncryptionKey"] ?? "";
                            var password = PassGenService.GeneratePassword(12, PassGenService.Complexity.High);
                            string escapedUser = EscapeShellSingleQuotedValue(user);
                            string escapedPassword = EscapeShellSingleQuotedValue(password);
                            var command = client.CreateCommand($"echo '{escapedUser}:{escapedPassword}' | sudo chpasswd");
                            string encryptedPassword = CryptorService.Cryptor.EncryptString(password, encryptionKey);
                            command.Execute();
                            if (command.ExitStatus != 0)
                            {
                                throw new Exception($"Error executing command: {command.Error}");
                            }

                            var newpassword = new Password
                            {
                                Username = user,
                                Servername = hostname,
                                EncryptedPassword = encryptedPassword,
                                AddTime = DateTime.Now
                            };
                            _context.Add(newpassword);
                        }

                        await _context.SaveChangesAsync();
                    }
                    client.Disconnect();
                    return ("Success");
                }
                catch (Exception ex)
                {
                    return ex.Message;
                }
            }
        }

        private static bool IsValidUnixUsername(string username)
        {
            return !string.IsNullOrWhiteSpace(username) && UnixUsernameRegex.IsMatch(username);
        }

        private static string EscapeShellSingleQuotedValue(string value)
        {
            return value.Replace("'", "'\"'\"'");
        }
    }
}
