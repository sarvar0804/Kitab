using Microsoft.EntityFrameworkCore.Internal;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Linq;
using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Kitab.Entities.AppUser;
using Kitab.Entities.Address;

namespace Kitab.DataAccess.Context
{
    public class DatabaseIdentityContextSeed
    {
        public static async Task SeedUserAsync(UserManager<AppUser> userManager,ILoggerFactory loggerFactory)
        {
            try
            {
                
                if (!userManager.Users.Any())
                {
                    var user = new AppUser
                    {
                        DisplayName="Behruz",
                        Email="bbahodirov.dev@gmail.com",
                        UserName="bbahodirov",
                        Address=new AddressEntity
                        {
                            FirstName="Behruz",
                            LastName="Bahodirov",
                            City="Tashkent",
                            State= "Tashkent",
                            Street= "Tashkent",
                            Zipcode="100000"
                        }
                    };
                    await userManager.CreateAsync(user, "1");
                   
                }
            }
            catch (Exception ex)
            {
                var logger = loggerFactory.CreateLogger<DatabaseContextSeed>();
                logger.LogError(ex, "An error occured during seeding data");
            }
        }
    }
}
