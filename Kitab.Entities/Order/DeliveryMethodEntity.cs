﻿using Kitab.Entities.Base;
using System;
using System.Collections.Generic;
using System.Text;

namespace Kitab.Entities
{
    public class DeliveryMethodEntity : BaseEntity
    {
        public string ShortName { get; set; }
        public string DeliveryTime { get; set; }
        public string Description { get; set; }
        public decimal Price { get; set; }
    }
}
