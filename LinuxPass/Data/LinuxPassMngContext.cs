using LinuxPass.Models;
using Microsoft.EntityFrameworkCore;

namespace LinuxPass.Data;

public partial class LinuxPassMngContext : DbContext
{
    public LinuxPassMngContext()
    {
    }

    public LinuxPassMngContext(DbContextOptions<LinuxPassMngContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Password> Passwords { get; set; }

    public DbSet<LinuxPass.Models.Server> Servers { get; set; } = default!;

    //protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    //    => optionsBuilder.UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=Linux_PassMNG;Trusted_Connection=True;MultipleActiveResultSets=true");

    //protected override void OnModelCreating(ModelBuilder modelBuilder)
    //{
    //    modelBuilder.Entity<Password>(entity =>
    //    {
    //        entity.HasKey(e => e.Id)
    //            .HasName("PK__Lnx_Pass__3214EC07DFABC34A")
    //            .HasFillFactor(80);
    //    });

    //    OnModelCreatingPartial(modelBuilder);
    //}

    //partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
