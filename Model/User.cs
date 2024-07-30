using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNetCore.Identity;

namespace ValidateJwtToken.Model
{
    public class User: IdentityUser
    {
        public string? User_type { get; set; }
    }
}
