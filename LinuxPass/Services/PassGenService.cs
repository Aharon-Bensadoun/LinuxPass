using System.Text;

namespace LinuxPass.Services
{
    public class PassGenService
    {
        private static readonly Random random = new Random();
        private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
        private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string Digits = "0123456789";
        private const string SpecialCharacters = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        public enum Complexity
        {
            Low,
            Medium,
            High
        }
        public static string GeneratePassword(int length, Complexity complexity)
        {
            StringBuilder password = new StringBuilder();
            string characterSet = Lowercase;

            switch (complexity)
            {
                case Complexity.Medium:
                    characterSet += Uppercase + Digits;
                    break;
                case Complexity.High:
                    characterSet += Uppercase + Digits + SpecialCharacters;
                    break;
            }

            for (int i = 0; i < length; i++)
            {
                password.Append(characterSet[random.Next(characterSet.Length)]);
            }

            return password.ToString();
        }
    }
}
