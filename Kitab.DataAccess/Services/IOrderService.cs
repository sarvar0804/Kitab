using System.Collections.Generic;
using System.Threading.Tasks;
using Kitab.Entities;

namespace Kitab.DataAccess
{
    public interface IOrderService
    {
        Task<OrderEntity> CreateOrderAsync(string buyerEmail, int deliveryMethod, string basketId, AddressAggregate shippingAddress);
        Task<IReadOnlyList<OrderEntity>> GetOrdersForUserAsync(string buyerEmail);
        Task<OrderEntity> GetOrderByIdAsync(int id,string buyerEmail);
        Task<IReadOnlyList<DeliveryMethodEntity>> GetDeliveryMethodsAsync();
    }
}
