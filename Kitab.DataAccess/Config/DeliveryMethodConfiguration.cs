﻿using Kitab.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;

namespace Kitab.DataAccess
{
    public class DeliveryMethodConfiguration : IEntityTypeConfiguration<DeliveryMethodEntity>
    {
        public void Configure(EntityTypeBuilder<DeliveryMethodEntity> builder)
        {
            builder.ToTable("tDeliveryMethod", "dbo");
            builder.HasKey(a => a.Id);
            builder.Property(s => s.Price).HasColumnType("decimal(18,2)");
        }
    }
}
