using System.Text.RegularExpressions;

namespace LinuxPass.Services
{
    internal static partial class ShellCommandSafety
    {
        private static readonly Regex UnixUsernameRegex = UnixUsernamePattern();

        public static void ValidateUnixUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username) || !UnixUsernameRegex.IsMatch(username))
            {
                throw new ArgumentException("Invalid Unix username.", nameof(username));
            }
        }

        public static string SingleQuote(string value)
            => $"'{(value ?? string.Empty).Replace("'", "'\"'\"'")}'";

        [GeneratedRegex("^[a-z_][a-z0-9_-]{0,31}[$]?$", RegexOptions.CultureInvariant)]
        private static partial Regex UnixUsernamePattern();
    }
}
