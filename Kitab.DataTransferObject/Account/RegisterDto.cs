using System;
using System.Collections.Generic;
using System.Text;

namespace Kitab.DataTransferObject
{
    public class RegisterDto
    {
        public string Email { get; set; }
        public string DisplayName { get; set; }
        public string Password { get; set; }
    }
}
