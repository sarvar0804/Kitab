﻿using Kitab.Entities.Base;
using System;
using System.Collections.Generic;
using System.Text;

namespace Kitab.Entities
{
    public class OrderItemEntity : BaseEntity
    {
        public OrderItemEntity()
        {

        }
        public OrderItemEntity(ProductItemOrdered ıtemOrdered, decimal price, int quantity)
        {
            ItemOrdered = ıtemOrdered;
            Quantity = quantity;
            Price = price;
        }
        public ProductItemOrdered ItemOrdered { get; set; }
        public int Quantity { get; set; }
        public decimal Price { get; set; }
    }
}
