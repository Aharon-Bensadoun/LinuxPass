using System.Net;

namespace LinuxPass.Services
{
    public class SendSMSService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;

        public SendSMSService(IConfiguration configuration, HttpClient httpClient)
        {
            _configuration = configuration;
            _httpClient = httpClient;
        }

        public async Task<string> SendSMSAsync(string smsPhone)
        {
            string smsMessage = _configuration["SMSSettings:SMSMessage"] ?? string.Empty;
            string smsSendMethod = _configuration["SMSSettings:SMSSendMethod"] ?? string.Empty;
            string requestorID = _configuration["SMSSettings:RequestorID"] ?? string.Empty;
            string apiUrl = _configuration["SMSSettings:APIURL"] ?? string.Empty;

            if (string.IsNullOrWhiteSpace(apiUrl))
            {
                return "SMS sending is disabled: API URL is not configured.";
            }

            string encodedMessage = WebUtility.UrlEncode(smsMessage);
            string encodedPhone = WebUtility.UrlEncode(smsPhone);
            string encodedMethod = WebUtility.UrlEncode(smsSendMethod);
            string encodedRequestorId = WebUtility.UrlEncode(requestorID);
            string url = $"{apiUrl}?SMSMessage={encodedMessage}&SMSPhone={encodedPhone}&SMSSendMethod={encodedMethod}&RequestorID={encodedRequestorId}";

            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync(url);

                return response.IsSuccessStatusCode
                    ? "SMS request submitted successfully."
                    : $"Error: {response.StatusCode}";
            }
            catch (Exception ex)
            {
                return $"Exception occurred: {ex.Message}";
            }
        }
    }
}
