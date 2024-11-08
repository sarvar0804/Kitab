﻿using AutoMapper;
using Kitab.DataTransferObject;
using Kitab.DataTransferObject.ProductType;
using Kitab.Entities;
using Kitab.Entities.Address;
using Kitab.Entities.Basket;
using Kitab.Util.Resolvers;

namespace Kitab.Util.Mapping
{
    public class MappingProfiles : Profile
    {
        public MappingProfiles()
        {
            CreateMap<ProductEntity, ProductToReturnDto>()
                .ForMember(d => d.ProductBrand, o => o.MapFrom(s => s.ProductBrand.Name))
                .ForMember(d => d.ProductType, o => o.MapFrom(s => s.ProductType.Name))
                .ForMember(d => d.PictureUrl, o => o.MapFrom<ProductUrlResolver>());

            CreateMap<ProductBrandEntity, ProductBrandToReturnDto>()
                .ForMember(d => d.Name, o => o.MapFrom(s => s.Name))
                .ForMember(d => d.Id, o => o.MapFrom(s => s.Id));

            CreateMap<ProductTypeEntity, ProductTypeToReturnDto>()
              .ForMember(d => d.Name, o => o.MapFrom(s => s.Name))
              .ForMember(d => d.Id, o => o.MapFrom(s => s.Id));
            
            CreateMap<AddressEntity, AddressDto>();
            CreateMap<AddressDto, AddressEntity>();

            CreateMap<AddressEntity, AddressAggregate>();
            CreateMap<AddressAggregate, AddressDto>();

            CreateMap<AddressAggregate, AddressDto>();
            CreateMap<AddressDto, AddressAggregate>();

            CreateMap<BasketEntity, BasketDto>();
            CreateMap<BasketDto, BasketEntity>();

            CreateMap<BasketItemEntity, BasketItemDto>();
            CreateMap<BasketItemDto, BasketItemEntity>();

            CreateMap<OrderEntity, OrderDto>();
            CreateMap<OrderDto, OrderEntity>();

            CreateMap<OrderEntity, OrdertoReturnDto>()
                .ForMember(d=>d.DeliveryMethod, o=>o.MapFrom(s=>s.DeliveryMethod.ShortName))
                .ForMember(d => d.ShippingPrice, o => o.MapFrom(s => s.DeliveryMethod.Price))
                .ForMember(d => d.DeliveryMethod, o => o.MapFrom(s => s.DeliveryMethod.ShortName));
            CreateMap<OrdertoReturnDto, OrderEntity>();

            CreateMap<OrderItemEntity, OrderItemDto>()
                 .ForMember(d => d.ProductId, o => o.MapFrom(s => s.ItemOrdered.ProductItemId))
                 .ForMember(d => d.ProductName, o => o.MapFrom(s => s.ItemOrdered.ProductName))
                 .ForMember(d => d.PictureUrl, o => o.MapFrom(s => s.ItemOrdered.PictureUrl))
                 .ForMember(d => d.PictureUrl, o => o.MapFrom<OrderItemResolver>());
        }
    }
}
