using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    internal static partial class ShellCommandHelper
    {
        [GeneratedRegex("^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant)]
        private static partial Regex UnixUsernameRegex();

        public static string ValidateUnixUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username) || !UnixUsernameRegex().IsMatch(username))
            {
                throw new ArgumentException("Invalid Unix username.", nameof(username));
            }

            return username;
        }

        public static string EscapeSingleQuotedValue(string value)
        {
            ArgumentNullException.ThrowIfNull(value);
            return value.Replace("'", "'\"'\"'");
        }
    }
}
