using LinuxPass.Data;
using LinuxPass.Models;
using Renci.SshNet;

namespace LinuxPass.Services
{
    public class ResetPassService
    {
        private readonly LinuxPassMngContext _context;
        private readonly IConfiguration _configuration;

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
                            string encryptionKey = _configuration["EncryptionKey"] ?? "";
                            // Generate a password
                            var password = PassGenService.GeneratePassword(12, PassGenService.Complexity.High);
                            var command = client.CreateCommand($"echo '{user}:{password}' | sudo chpasswd");
                            // Encrypt the password
                            string encryptedPassword = CryptorService.Cryptor.EncryptString(password, encryptionKey);
                            // Decrypt the password
                            string decryptedPassword = CryptorService.Cryptor.DecryptString(encryptedPassword, encryptionKey);
                            // Reset the password for each user
                            var resetpassresult = command.Execute();
                            // Insert the password to the database  
                            var newpassword = new Password
                            {
                                Username = user,
                                Servername = hostname,
                                EncryptedPassword = encryptedPassword,
                                AddTime = DateTime.Now
                            };
                            _context.Add(newpassword);
                            await _context.SaveChangesAsync();
                        }
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
    }
}