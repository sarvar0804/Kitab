using Kitab.Entities.AppUser;

namespace Kitab.DataAccess
{
    public interface ITokenService
    {
        string CreateToken(AppUser appUser);
    }
}
