using System.ComponentModel.DataAnnotations;

namespace LinuxPass.Models
{
    public partial class Server
    {
        [Key]
        public int Id { get; set; }
        public string HostSrvName { get; set; } = null!;
        public string HostSrvUsername { get; set; } = null!;
        public string? HostSrvPassword { get; set; }
        public string? HostSSHKeyPath { get; set; }
    }
}
