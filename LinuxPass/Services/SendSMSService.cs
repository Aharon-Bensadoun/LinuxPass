using System.Web;

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

            // Encode the message using HttpUtility.UrlEncode
            string encodedMessage = HttpUtility.UrlEncode(smsMessage);

            // Construct the URL for the API request
            string url = $"{apiUrl}?SMSMessage={encodedMessage}{decryptedPassword}&SMSPhone={smsPhone}&SMSSendMethod={smsSendMethod}&RequestorID={requestorID}";

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
