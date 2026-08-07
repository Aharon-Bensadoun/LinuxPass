namespace LinuxPass.Services
{
    public class SendSMSService
    {
        private readonly HttpClient _httpClient;

        public SendSMSService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public Task<string> SendSMSAsync(string smsPhone, string decryptedPassword)
        {
            if (string.IsNullOrWhiteSpace(smsPhone))
            {
                return Task.FromResult("Phone number is required.");
            }

            return Task.FromResult("Sending passwords by SMS has been disabled for security reasons.");
        }
    }
}
