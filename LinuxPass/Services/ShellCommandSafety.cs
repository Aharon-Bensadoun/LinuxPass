using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    internal static class ShellCommandSafety
    {
        private static readonly Regex UnixUsernamePattern = new("^[a-z_][a-z0-9_-]*[$]?$", RegexOptions.CultureInvariant);

        public static void ValidateUnixUsername(string username, string paramName)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("Value cannot be null or whitespace.", paramName);
            }

            if (!UnixUsernamePattern.IsMatch(username))
            {
                throw new ArgumentException("Value is not a valid Unix username.", paramName);
            }
        }

        public static string EscapeSingleQuotedShellArgument(string value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            return value.Replace("'", "'\"'\"'");
        }
    }
}
