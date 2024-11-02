using System.ComponentModel.DataAnnotations;
using Kitab.Entities.Base;

namespace Kitab.Entities.Address
{
    public class AddressEntity : BaseEntity
    {

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Street { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Zipcode { get; set; }
        [Required]

        public string AppUserId { get; set; }
        public new AppUser.AppUser AppUser { get; set; }
    }
}
