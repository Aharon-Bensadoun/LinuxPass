using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    internal static class ShellCommandSafety
    {
        private static readonly Regex UnixUserNameRegex = new("^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant);

        public static string ValidateUnixUserName(string username, string parameterName = "username")
        {
            if (string.IsNullOrWhiteSpace(username) || !UnixUserNameRegex.IsMatch(username))
            {
                throw new ArgumentException("Invalid Unix username.", parameterName);
            }

            return username;
        }

        public static string EscapeSingleQuoted(string value)
        {
            return (value ?? string.Empty).Replace("'", "'\"'\"'");
        }
    }
}
