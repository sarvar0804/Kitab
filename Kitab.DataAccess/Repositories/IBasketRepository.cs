using Kitab.Entities.Basket;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Kitab.DataAccess.Repositories
{
    public interface IBasketRepository
    {
        Task<BasketEntity> GetBasketAsync(string basketId);
        Task<BasketEntity> UpdateBasketAsync(BasketEntity basketEntity);
        Task<bool> DeleteBasketAsync(string basketId);
    }
}
