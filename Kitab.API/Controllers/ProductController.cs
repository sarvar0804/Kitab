using AutoMapper;
using Kitab.API.Helpers;
using Kitab.DataAccess.Repositories;
using Kitab.DataAccess.Specification;
using Kitab.DataTransferObject;
using Kitab.DataTransferObject.ProductType;
using Kitab.Entities;
using Kitab.Util.Errors;
using Kitab.Util.Helpers;
using Kitab.WebAPI.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kitab.API.Controllers
{
    public class ProductController : BaseApiController
    {
        private readonly IProductRepository _productRepo;
       
        private readonly IMapper _mapper;
        public ProductController(IProductRepository productsRepo, IMapper mapper)
        {
            _productRepo = productsRepo;
            _mapper = mapper;
        }

        [Cached(600)]
        [Route("[action]")]
        [HttpGet]
        public async Task<ActionResult<List<ProductBrandToReturnDto>>> GetProductBrands()
        {
            var list = await _productRepo.GetProductBrandsAsync();

            return Ok(_mapper.Map<List<ProductBrandToReturnDto>>(list));

        }
        [Cached(600)]
        [Route("[action]")]
        [HttpGet]
        public async Task<ActionResult<List<ProductTypeToReturnDto>>> GetProductTypes()
        {
            var list = await _productRepo.GetProductTypesAsync();

            return Ok(_mapper.Map<List<ProductTypeToReturnDto>>(list));

        }
        [Cached(600)]
        [HttpGet("{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
        public async Task<ActionResult<ProductToReturnDto>> GetProduct(int id)
        {
            var spec = new ProductsWithTypesAndBrandsSpecification(id);

            var productEntity = await _productRepo.GetEntityWithSpec(spec);

            if (productEntity == null) return NotFound(new ApiResponse(404));

            return Ok(_mapper.Map<ProductToReturnDto>(productEntity));

        }
        
        [Cached(600)]
        [HttpGet]
        public async Task<ActionResult<Pagination<ProductToReturnDto>>> GetProducts([FromQuery]ProductSpecParam productSpecParam)
        {
            var spec = new ProductsWithTypesAndBrandsSpecification(productSpecParam);

            var countSpec = new ProductsWithFiltersForCountSpecification(productSpecParam);

            var totalItems = await _productRepo.CountAsync(countSpec);

            var productEntities = await _productRepo.ListAsync(spec);

            var data = _mapper.Map<IReadOnlyList<ProductEntity>, IReadOnlyList<ProductToReturnDto>>(productEntities);

            return Ok(new Pagination<ProductToReturnDto>(productSpecParam.PageIndex, productSpecParam.PageSize,totalItems,data));
        }
    }
}
