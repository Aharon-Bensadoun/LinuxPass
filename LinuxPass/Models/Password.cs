using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LinuxPass.Models;

public partial class Password
{
    [Key]
    public int Id { get; set; }

    [Column("username")]
    [StringLength(15)]
    [Required]
    [RegularExpression("^[a-z_][a-z0-9_-]*[$]?$", ErrorMessage = "Username must be a valid Unix account name.")]
    [Unicode(false)]
    public string Username { get; set; } = null!;

    [Column("servername")]
    [StringLength(15)]
    [Unicode(false)]
    public string Servername { get; set; } = null!;

    [Column("encrypted_password")]
    [Unicode(false)]
    public string EncryptedPassword { get; set; } = null!;

    [Column("add_time", TypeName = "datetime")]
    public DateTime AddTime { get; set; }
}
