using Kitab.Entities;
using Kitab.Entities.Basket;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Kitab.DataAccess
{
    public interface IPaymentService
    {
        Task<BasketEntity> CreateOrUpdatePaymentIntent(string basketId);
        Task<OrderEntity> UpdateOrderPaymentSucceeded(string basketId);
        Task<OrderEntity> UpdateOrderPaymentFailed(string paymentIntentId);

    }
}
