using Kitab.Entities;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Kitab.DataAccess.Context;
using Microsoft.EntityFrameworkCore;

namespace Kitab.DataAccess.Repositories
{
    public class OrderRepository : BaseRepository<OrderEntity>, IOrderRepository
    {
        private readonly DatabaseContext _context;
        public OrderRepository(DatabaseContext context) : base(context)
        {
            _context = context;
        }
    }
}
