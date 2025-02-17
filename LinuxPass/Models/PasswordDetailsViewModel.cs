namespace LinuxPass.Models
{
    public class PasswordDetailsViewModel
    {
        public int Id { get; set; }
        public required string Username { get; set; }
        public required string Servername { get; set; }
        public required string DecryptedPassword { get; set; }
    }
}
