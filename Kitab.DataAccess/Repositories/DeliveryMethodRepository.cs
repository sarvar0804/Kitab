using Kitab.Entities;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Kitab.DataAccess.Context;
using Microsoft.EntityFrameworkCore;

namespace Kitab.DataAccess.Repositories
{
    public class DeliveryMethodRepository : BaseRepository<DeliveryMethodEntity>, IDeliveryModethodRepository
    {
        private readonly DatabaseContext _context;
        public DeliveryMethodRepository(DatabaseContext context) : base(context)
        {
            _context = context;
        }
    }
}
