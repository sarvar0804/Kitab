using Kitab.DataAccess.IRepositories;
using Kitab.Entities.Base;
using System;
using System.Threading.Tasks;

namespace Kitab.DataAccess
{
    public interface IUnitOfWork : IDisposable
    {
        IBaseRepository<TEntity> Repository<TEntity>() where TEntity : BaseEntity;
        Task<int> Complete();
    }
}
