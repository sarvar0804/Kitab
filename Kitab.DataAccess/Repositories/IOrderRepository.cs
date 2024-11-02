using Kitab.DataAccess.IRepositories;
using Kitab.Entities;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Kitab.DataAccess.Repositories
{
    public interface IOrderRepository :IBaseRepository<OrderEntity>
    {
    }
}
