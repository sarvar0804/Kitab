using Kitab.Entities;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Text;

namespace Kitab.DataAccess.Specification
{
    public class OrderByPaymentIntentIdSpecification : BaseSpecification<OrderEntity>
    {
        public OrderByPaymentIntentIdSpecification
            (string paymentId) : base(o => o.PaymentIntentId == paymentId)
        {
        }
    }
}
