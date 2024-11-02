using Kitab.Entities.Address;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace Kitab.Entities.AppUser
{
    public class AppUser : IdentityUser
    {
        public string DisplayName { get; set; }

        public AddressEntity Address { get; set; }
    }
}
