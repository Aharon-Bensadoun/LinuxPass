using Microsoft.AspNetCore.WebUtilities;

namespace LinuxPass.Services
{
    public class SendSMSService
    {
        private readonly IConfiguration _configuration;

        public SendSMSService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<string> SendSMSAsync(string smsPhone, string decryptedPassword)
        {
            string smsMessage = _configuration["SMSSettings:SMSMessage"] ?? "";
            string smsSendMethod = _configuration["SMSSettings:SMSSendMethod"] ?? "";
            string requestorID = _configuration["SMSSettings:RequestorID"] ?? "";
            string apiUrl = _configuration["SMSSettings:APIURL"] ?? "";

            var queryParameters = new Dictionary<string, string?>
            {
                ["SMSMessage"] = $"{smsMessage}{decryptedPassword}",
                ["SMSPhone"] = smsPhone,
                ["SMSSendMethod"] = smsSendMethod,
                ["RequestorID"] = requestorID
            };

            // Construct the URL with safely encoded query-string parameters
            string url = QueryHelpers.AddQueryString(apiUrl, queryParameters);

            using (HttpClient client = new HttpClient())
            {
                try
                {
                    // Send the GET request
                    HttpResponseMessage response = await client.GetAsync(url);

                    if (response.IsSuccessStatusCode)
                    {
                        return "SMS sent successfully!";
                    }
                    else
                    {
                        return $"Error: {response.StatusCode}";
                    }
                }
                catch (Exception ex)
                {
                    return $"Exception occurred: {ex.Message}";
                }
            }
        }
    }
}
