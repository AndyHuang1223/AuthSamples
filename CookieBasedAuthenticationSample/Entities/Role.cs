namespace CookieBasedAuthenticationSample.Entities
{
    public class Role
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public RoleType RoleType { get; set; }
        public ICollection<UserRole> UserRoles { get; set; }
    }

    public enum RoleType
    {
        Normal,
        Admin
    }
}
