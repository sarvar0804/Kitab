using Kitab.Entities;
using Kitab.Entities.Address;
using Kitab.Entities.AppUser;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Kitab.DataAccess.Context
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
        {
        }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                // Decimal turlarini double ga o'zgartirish
                var decimalProperties = entityType.ClrType.GetProperties().Where(a => a.PropertyType == typeof(decimal));
                foreach (var property in decimalProperties)
                {
                    modelBuilder.Entity(entityType.Name).Property(property.Name).HasColumnType("numeric");
                }

                // DateTimeOffset turlarini timestamptz ga o'zgartirish
                var dateTimeOffsetProperties = entityType.ClrType.GetProperties().Where(a => a.PropertyType == typeof(DateTimeOffset));
                foreach (var property in dateTimeOffsetProperties)
                {
                    modelBuilder.Entity(entityType.Name).Property(property.Name).HasColumnType("timestamptz");
                }
            }

            // Konfiguratsiyalarni qo'shish
            modelBuilder.ApplyConfiguration(new DeliveryMethodConfiguration());
            modelBuilder.ApplyConfiguration(new OrderConfiguration());
            modelBuilder.ApplyConfiguration(new OrderItemConfiguration());
            modelBuilder.ApplyConfiguration(new ProductConfiguration());
            modelBuilder.ApplyConfiguration(new AppUserConfiguration());
            modelBuilder.ApplyConfiguration(new AddressConfiguration());

            // Barcha konfiguratsiyalarni joriy to'plamdan qo'shish
            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
        }

        public DbSet<AddressEntity> tAddress { get; set; }
        public DbSet<OrderEntity> tOrder { get; set; }
        public DbSet<OrderItemEntity> tOrderItem { get; set; }
        public DbSet<DeliveryMethodEntity> tDeliveryMethod { get; set; }
        public DbSet<ProductEntity> tProduct { get; set; }
        public DbSet<ProductBrandEntity> tProductBrand { get; set; }
        public DbSet<ProductTypeEntity> tProductType { get; set; }
    }
}
