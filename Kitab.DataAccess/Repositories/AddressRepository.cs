using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Kitab.DataAccess.Context;
using Microsoft.EntityFrameworkCore;
using Kitab.Entities.Address;

namespace Kitab.DataAccess.Repositories
{
    public class AddressRepository : BaseRepository<AddressEntity>, IAddressRepository
    {
        private readonly DatabaseContext _context;
        public AddressRepository(DatabaseContext context) : base(context)
        {
            _context = context;
        }
    }
}
