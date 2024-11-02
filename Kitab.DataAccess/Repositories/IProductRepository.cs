using Kitab.DataAccess.IRepositories;
using Kitab.Entities;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Kitab.DataAccess.Repositories
{
    public interface IProductRepository :IBaseRepository<ProductEntity>
    {
        Task<ProductEntity> GetProductByIdAsync(int id);
        Task<IReadOnlyList<ProductEntity>> GetProductsAsync();
        Task<IReadOnlyList<ProductBrandEntity>> GetProductBrandsAsync();
        Task<IReadOnlyList<ProductTypeEntity>> GetProductTypesAsync();
    }
}
