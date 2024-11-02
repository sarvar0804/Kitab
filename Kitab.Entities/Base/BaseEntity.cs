using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Kitab.Entities.Base
{
    public class BaseEntity
    {

        public int Id { get; set; }
        public AppUser.AppUser AppUser { get; set; }
    }
}
