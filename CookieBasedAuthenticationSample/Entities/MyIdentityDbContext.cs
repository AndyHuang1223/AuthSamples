using Microsoft.EntityFrameworkCore;
using CookieBasedAuthenticationSample.Extensions;

namespace CookieBasedAuthenticationSample.Entities
{
    public class MyIdentityDbContext : DbContext
    {
        public MyIdentityDbContext(DbContextOptions<MyIdentityDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("Users");
            modelBuilder.Entity<Role>().ToTable("Roles");
            modelBuilder.Entity<UserRole>().ToTable("UserRoles");

            // 建立種子資料（非必要，實務上密碼還需要進行雜湊加鹽等處理）
            modelBuilder.Entity<User>().HasData(new User { Id = 1, Email = "andy@gmail.com", Password = "111111".ToSHA256(), Name = "Andy" });
            modelBuilder.Entity<User>().HasData(new User { Id = 2, Email = "Admin@gmail.com", Password = "111111".ToSHA256(), Name = "Admin" });

            modelBuilder.Entity<Role>().HasData(new Role { Id = 1, Name = "Normal", RoleType = RoleType.Normal });
            modelBuilder.Entity<Role>().HasData(new Role { Id = 2, Name = "Admin", RoleType = RoleType.Admin });

            modelBuilder.Entity<UserRole>().HasData(new UserRole { Id = 1, RoleId = 1, UserId = 1 });
            modelBuilder.Entity<UserRole>().HasData(new UserRole { Id = 2, RoleId = 2, UserId = 1 });
            modelBuilder.Entity<UserRole>().HasData(new UserRole { Id = 3, RoleId = 2, UserId = 2 });
        }
    }
}
