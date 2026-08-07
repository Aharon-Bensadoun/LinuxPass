using System.Text.RegularExpressions;

namespace LinuxPass.Utilities
{
    public static partial class UnixUsernameValidator
    {
        [GeneratedRegex(@"^[a-z_][a-z0-9_-]{0,31}$", RegexOptions.CultureInvariant)]
        private static partial Regex UnixUsernameRegex();

        public static bool IsValid(string? username)
        {
            return !string.IsNullOrWhiteSpace(username) && UnixUsernameRegex().IsMatch(username);
        }
    }
}
