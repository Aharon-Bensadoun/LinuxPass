using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    internal static class ShellCommandHelper
    {
        private static readonly Regex UnixUsernameRegex = new("^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant);

        public static string ValidateUnixUsername(string username, string paramName)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("Username cannot be empty.", paramName);
            }

            if (!UnixUsernameRegex.IsMatch(username))
            {
                throw new ArgumentException("Username contains invalid Unix account characters.", paramName);
            }

            return username;
        }

        public static string EscapeSingleQuoted(string value)
        {
            return (value ?? string.Empty).Replace("'", "'\"'\"'");
        }
    }
}
