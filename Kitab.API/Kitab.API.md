Project Path: Kitab.API

Source Tree:

```
Kitab.API
├── appsettings.Development.json
├── appsettings.json
├── Attributes
│   └── CachedAttribute.cs
├── bin
│   ├── Debug
│   │   └── netcoreapp8.0
│   └── Release
│       └── netcoreapp8.0
├── Kitab.WebAPI.csproj
├── Controllers
│   ├── AccountController.cs
│   ├── BaseApiController.cs
│   ├── BasketController.cs
│   ├── BuggyController.cs
│   ├── ErrorController.cs
│   ├── OrderController.cs
│   ├── PaymentController.cs
│   ├── ProductController.cs
│   └── WeatherForecastController.cs
├── Extensions
│   ├── ClaimsPrincipalExtension.cs
│   ├── IdentityServiceExtension.cs
│   ├── StartupServicesExtension.cs
│   ├── SwaggerServiceExtension.cs
│   └── UserManagerExtension.cs
├── libman.json
├── obj
│   ├── Kitab.WebAPI.csproj.nuget.dgspec.json
│   ├── Kitab.WebAPI.csproj.nuget.g.props
│   ├── Kitab.WebAPI.csproj.nuget.g.targets
│   ├── Debug
│   │   └── netcoreapp8.0
│   │       ├── Kitab.WebAPI.AssemblyInfo.cs
│   │       ├── Kitab.WebAPI.AssemblyInfoInputs.cache
│   │       ├── Kitab.WebAPI.assets.cache
│   │       ├── Kitab.WebAPI.csproj.AssemblyReference.cache
│   │       ├── Kitab.WebAPI.csproj.FileListAbsolute.txt
│   │       ├── Kitab.WebAPI.GeneratedMSBuildEditorConfig.editorconfig
│   │       ├── ref
│   │       ├── refint
│   │       └── staticwebassets
│   ├── project.assets.json
│   ├── project.nuget.cache
│   ├── project.packagespec.json
│   ├── Release
│   │   └── netcoreapp8.0
│   │       ├── Kitab.WebAPI.AssemblyInfo.cs
│   │       ├── Kitab.WebAPI.AssemblyInfoInputs.cache
│   │       ├── Kitab.WebAPI.assets.cache
│   │       ├── Kitab.WebAPI.csproj.AssemblyReference.cache
│   │       ├── Kitab.WebAPI.csproj.CoreCompileInputs.cache
│   │       ├── Kitab.WebAPI.csproj.FileListAbsolute.txt
│   │       ├── Kitab.WebAPI.GeneratedMSBuildEditorConfig.editorconfig
│   │       ├── Kitab.WebAPI.MvcApplicationPartsAssemblyInfo.cache
│   │       ├── ref
│   │       ├── refint
│   │       └── staticwebassets
│   ├── rider.project.model.nuget.info
│   └── rider.project.restore.info
├── Program.cs
├── Properties
│   └── launchSettings.json
├── Startup.cs
├── WeatherForecast.cs
└── wwwroot
    └── images
        └── products
            ├── askimizeskibirroman.png
            ├── BenKirke.png
            ├── benorada.jpg
            ├── biromurnasilyasanir.jpg
            ├── clarissa.jpg
            ├── evkurallari.JPG
            ├── evsahibesi.jpg
            ├── gencbir.jpg
            ├── gorunmez.JPG
            ├── Gucler.jpg
            ├── hippi.jpg
            ├── KirmiziPazartesi.jpg
            ├── marifetler.jpg
            ├── raconnanindunyasi.jpg
            ├── sarisicak.jpg
            ├── sesler.jpg
            ├── suskunlar.jpg
            └── uckizkardes.jpg

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\appsettings.Development.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Information",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "Connectionstrings": {
    "DefaultConnectionString": "Data Source=Kitab.db",
    "Redis": "localhost"
  },
  "Token": {
    "Key": "super secret key",
    "Issuer": "http://localhost:63484/"
  },
  "ApiUrl": "http://localhost:63484/"
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "StripeSettings": {
    "PublishibleKey": "pk_test_51Hv2RBJQtbwvMUmCUoy5cr0sfkRPsBQLK1CcKX3omdl5Rj1Fnrkws6mW0YjqKC8JcUuR61RaCFcyP50muiYglxWc00EWKghGgO",
    "SecretKey": "sk_test_51Hv2RBJQtbwvMUmCAk91imOGj2yQyk5HOsBj6EH0RP7KyusLvkMmBz6rPNtDFQXdTNRsVhszrgFF5xMNLRD2yCBn00cdpRY3LV"
  },
  "AllowedHosts": "*",
  "Connectionstrings": {
    "DefaultConnectionString": "Data Source=Kitab.db",
    "Redis": "localhost"
  }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Attributes\CachedAttribute.cs`:

```cs
﻿using Kitab.DataAccess;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kitab.API.Helpers
{
    public class CachedAttribute : Attribute, IAsyncActionFilter
    {
        private readonly int _timeToLiveSeconds;
        public CachedAttribute(int timeToLiveSeconds)
        {
            _timeToLiveSeconds = timeToLiveSeconds;
        }
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var responseService = context.HttpContext.RequestServices.GetRequiredService<IResponseCacheService>();
            var cacheKey = GenerateCacheKeyFromRequest(context.HttpContext.Request);
            var cachedResponse = await responseService.GetCachedResponseAsync(cacheKey);
            if (!string.IsNullOrEmpty(cachedResponse))
            {
                var contentResult = new ContentResult
                {
                    Content = cachedResponse,
                    ContentType = "application/json",
                    StatusCode = 200
                };
                context.Result = contentResult;
                return;
            }
            var executedContent = await next(); // movw to controller
            if (executedContent.Result is OkObjectResult okObject)
            {
                await responseService.CacheResponseAsync(cacheKey, okObject.Value, TimeSpan.FromSeconds(_timeToLiveSeconds));
            }
        }

        private string GenerateCacheKeyFromRequest(HttpRequest request)
        {
            var keyBuilder = new StringBuilder();
            keyBuilder.Append($"{request.Path}");

            foreach (var (key, value) in request.Query.OrderBy(x => x.Key))
            {
                keyBuilder.Append($"|{key}-{value}");
            }
            return keyBuilder.ToString();
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Kitab.WebAPI.csproj`:

```csproj
<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>netcoreapp8.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.10" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="8.0.10" />
    <PackageReference Include="Swashbuckle.AspNetCore.SwaggerGen" Version="6.9.0" />
    <PackageReference Include="Swashbuckle.AspNetCore.SwaggerUI" Version="6.9.0" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\Kitab.DataAccess\Kitab.DataAccess.csproj" />
    <ProjectReference Include="..\Kitab.Util\Kitab.Util.csproj" />
  </ItemGroup>

  <ItemGroup>
    <Folder Include="wwwroot\images\products\" />
  </ItemGroup>


</Project>

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\AccountController.cs`:

```cs
﻿using Kitab.DataAccess;
using Kitab.DataTransferObject;
using Kitab.Util.Errors;
using Kitab.WebAPI.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using AutoMapper;
using Kitab.DataAccess.Repositories;
using System.Linq;
using System;
using Kitab.Entities.AppUser;
using Kitab.Entities.Address;

namespace Kitab.WebAPI.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly ITokenService _tokenService;
        private readonly IMapper _mapper;
        public AccountController(UserManager<AppUser> userManager, 
                                 SignInManager<AppUser> signInManager,
                                 ITokenService tokenService, IMapper mapper)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _mapper = mapper;
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("getcurrentuser")]
        public async Task<ActionResult<AppUserDto>> GetCurrentUser()
        {
            var user = await _userManager.FindByEmailFromClaimsPrincipalAsync(HttpContext.User);
            if (user == null) return Ok(new AppUserDto());
            return Ok(new AppUserDto
            {
                Email = user.Email,
                Token = _tokenService.CreateToken(user),
                DisplayName = user.DisplayName
            });
        }
        [HttpGet("emailexists")]
        public async Task<ActionResult<bool>> CheckEmailExistsAsync([FromQuery] string email)
        {
            return await _userManager.FindByEmailAsync(email) != null;
        }

        [Route("[action]")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet]
        public async Task<ActionResult<AddressDto>> GetUserAddress()
        {
            var user = await _userManager.FindUserByClaimsPrincipleWithAddressAsync(HttpContext.User);
         
            return _mapper.Map<AddressEntity, AddressDto>(user.Address);
        }

        [HttpPut("address")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<ActionResult<AddressDto>> UpdateUserAddress(AddressDto model)
        {
            var user = await _userManager.FindUserByClaimsPrincipleWithAddressAsync(HttpContext.User);

            user.Address = _mapper.Map<AddressDto, AddressEntity>(model);
            var result = await _userManager.UpdateAsync(user);
            if(!result.Succeeded) return BadRequest(new ApiResponse(500));
            return Ok(_mapper.Map<AddressEntity, AddressDto>(user.Address));
        }
        [HttpPost("login")]
        public async Task<ActionResult<AppUserDto>> Login(LoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return Unauthorized(new ApiResponse(401));
            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!result.Succeeded) return Unauthorized(new ApiResponse(401));
            return Ok(new AppUserDto
            {
                Email = user.Email,
                Token = _tokenService.CreateToken(user),
                DisplayName = user.DisplayName
            });
        }
        [HttpPost("register")]
        public async Task<ActionResult<AppUserDto>> Register([FromBody] RegisterDto model)
        {
            try 
            {
                if (CheckEmailExistsAsync(model.Email).Result.Value)
                {
                    return new BadRequestObjectResult(new ApiValidationErrorResponse 
                    { 
                        Errors = new[] { "Email adresi kullanılmaktadır." } 
                    });
                }
                
                var user = new AppUser
                {
                    Email = model.Email,
                    UserName = model.Email,
                    DisplayName = model.DisplayName
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                
                if (!result.Succeeded) 
                {
                    var errors = result.Errors.Select(e => e.Description).ToArray();
                    return BadRequest(new ApiValidationErrorResponse { Errors = errors });
                }
                
                return Ok(new AppUserDto
                {
                    Email = user.Email,
                    Token = _tokenService.CreateToken(user),
                    DisplayName = user.DisplayName
                });
            }
            catch (Exception)
            {
                // Log the exception
                return StatusCode(500, new ApiResponse(500, "Foydalanuvchini ro'yxatdan o'tkazishda xatolik yuz berdi"));
            }
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\BaseApiController.cs`:

```cs
﻿using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kitab.WebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BaseApiController : ControllerBase
    {

    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\BasketController.cs`:

```cs
﻿using AutoMapper;
using Kitab.DataAccess.Repositories;
using Kitab.DataTransferObject;
using Kitab.Entities.Basket;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kitab.WebAPI.Controllers
{
    public class BasketController : BaseApiController
    {
        private readonly IBasketRepository _basketRepository;
        private readonly IMapper _mapper;
        public BasketController(IBasketRepository basketRepository, IMapper mapper)
        {
            _basketRepository = basketRepository;
            _mapper = mapper;
        }
        [HttpGet]
        public async Task<ActionResult<BasketEntity>> GetBasketById(string id)
        {
            var basket = await _basketRepository.GetBasketAsync(id);
            return Ok(basket?? new BasketEntity(id));
        }
        [HttpPost]
        public async Task<ActionResult<BasketEntity>> UpdateBasket(BasketDto basket)
        {
            var updatedBasket = await _basketRepository.UpdateBasketAsync(_mapper.Map<BasketDto,BasketEntity>(basket));
            return Ok(updatedBasket);
        }
        [HttpDelete]
        public async Task DeleteBasket(string id)
        {
             await _basketRepository.DeleteBasketAsync(id);
            
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\BuggyController.cs`:

```cs
﻿using Kitab.DataAccess.Context;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kitab.WebAPI.Controllers
{
    public class BuggyController :BaseApiController
    {
        private readonly DatabaseContext _context;
        public BuggyController(DatabaseContext context)
        {
            _context = context;
        }
        [HttpGet("notfound")]
        public ActionResult GetNotFoundRequest()
        {
            return NotFound();
        }
        [HttpGet("servererror")]
        public ActionResult GetServerError()
        {
            return BadRequest();
        }
        [HttpGet("basrequest")]
        public ActionResult GetBadRequest()
        {
            return Ok();
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\ErrorController.cs`:

```cs
﻿using Kitab.Util.Errors;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kitab.WebAPI.Controllers
{
    [Route("errors/{code}")]
    [ApiExplorerSettings(IgnoreApi = true)]
    public class ErrorController : BaseApiController
    {
        public IActionResult Error(int code)
        {
            return new ObjectResult(new ApiResponse(code));
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\OrderController.cs`:

```cs
﻿using AutoMapper;
using Kitab.DataAccess;
using Kitab.DataTransferObject;
using Kitab.Entities;
using Kitab.Util.Errors;
using Kitab.WebAPI.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kitab.WebAPI.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class OrderController : BaseApiController
    {
        private IMapper _mapper { get; set; }
        private IOrderService _orderService { get; }
        public OrderController(IOrderService orderService, IMapper mapper)
        {
            _orderService = orderService;
            _mapper = mapper;
        }

        [Route("[action]")]
        [HttpPost]
        public async Task<ActionResult<OrderEntity>> CreateOrder(OrderDto model)
        {
            var email = HttpContext.User.RetrieveEmailFromPrincipal();
            var address = _mapper.Map<AddressDto, AddressAggregate>(model.ShipToAddress);
            var order = await _orderService.CreateOrderAsync(email,model.DeliveryMethodId,model.BasketId,address);
            if (order == null) return BadRequest(new ApiResponse(400,"Sipariş oluşturma aşamasında bir hata oluştu."));
            return Ok(order);
        }
        
        [Route("[action]")]
        [HttpGet]
        public async Task<ActionResult<IReadOnlyList<OrdertoReturnDto>>> GetOrdersForUser()
        {
            var email = HttpContext.User.RetrieveEmailFromPrincipal();
            var orders = await _orderService.GetOrdersForUserAsync(email);
            var result = _mapper.Map<IReadOnlyList<OrderEntity>, IReadOnlyList<OrdertoReturnDto>>(orders);
            return Ok(result);
        }

        [Route("[action]")]
        [HttpGet]
        public async Task<ActionResult<OrdertoReturnDto>> GetOrderByIdForUser(int id)
        {
            var email = HttpContext.User.RetrieveEmailFromPrincipal();
            var order = await _orderService.GetOrderByIdAsync(id,email);
            if (order == null) return NotFound(new ApiResponse(404));
            var result = _mapper.Map<OrderEntity, OrdertoReturnDto>(order);
            return Ok(result);
        }
        [Route("[action]")]
        [HttpGet]
        public async Task<ActionResult<DeliveryMethodEntity>> GetDeliveryMethods()
        {
            return Ok(await _orderService.GetDeliveryMethodsAsync());
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\PaymentController.cs`:

```cs
﻿using Kitab.DataAccess;
using Kitab.Entities;
using Kitab.Entities.Basket;
using Kitab.Util.Errors;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Stripe;
using System.IO;
using System.Threading.Tasks;

namespace Kitab.WebAPI.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
   
    public class PaymentController : BaseApiController
    {
        private readonly IPaymentService _paymentService;
        private readonly ILogger _logger;
        private const string WhSecret = "";

        public PaymentController(IPaymentService paymentService, ILogger<IPaymentService> logger)
        {
            this._logger = logger;
            this._paymentService = paymentService;
        }

        [Route("[action]")]
        [HttpPost]
        public async Task<ActionResult<BasketEntity>> CreateOrUpdatePaymentIntent(string basketId)
        {
            var basket = await _paymentService.CreateOrUpdatePaymentIntent(basketId);

            if (basket == null) return BadRequest(new ApiResponse(400,"Sepet bilgilerine erişilemedi"));

            return basket;
        }
        [Route("[action]")]
        [HttpPost]
        public async Task<ActionResult> StripeWebHook()
        {
            var json = await new StreamReader(HttpContext.Request.Body).ReadToEndAsync();

            var stripeEvent = EventUtility.ConstructEvent(json, Request.Headers["Stripe-Signature"], WhSecret);

            PaymentIntent paymentIntent;
            OrderEntity orderEntity;

            switch (stripeEvent.Type)
            {
                case "payment_intent.succeeded":
                    paymentIntent = (PaymentIntent)stripeEvent.Data.Object;
                    this._logger.LogInformation("Payment succceded : " , paymentIntent.Id);
                    orderEntity = await _paymentService.UpdateOrderPaymentSucceeded(paymentIntent.Id);
                    this._logger.LogInformation("Order updated to payment succceded : ", orderEntity.Id);

                    break;
                case "payment_intent.failed":
                    paymentIntent = (PaymentIntent)stripeEvent.Data.Object;
                    this._logger.LogInformation("Payment failed : ", paymentIntent.Id);
                    orderEntity = await _paymentService.UpdateOrderPaymentFailed(paymentIntent.Id);
                    this._logger.LogInformation("Order updated to payment failed : ", orderEntity.Id);
                    break;
            }
            return new EmptyResult();
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\ProductController.cs`:

```cs
﻿using AutoMapper;
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

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Controllers\WeatherForecastController.cs`:

```cs
﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Kitab.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [ApiExplorerSettings(IgnoreApi = true)]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Extensions\ClaimsPrincipalExtension.cs`:

```cs
﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Kitab.WebAPI.Extensions
{
    public static class ClaimsPrincipalExtension
    {
        public static string RetrieveEmailFromPrincipal(this ClaimsPrincipal user)
        {
            return user?.Claims?.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Extensions\IdentityServiceExtension.cs`:

```cs
﻿using Kitab.DataAccess.Context;
using Kitab.Entities.AppUser;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Kitab.WebAPI.Extensions
{
    public static class IdentityServiceExtension
    {
        public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
        {
            var builder = services.AddIdentityCore<AppUser>();
            builder = new IdentityBuilder(builder.UserType, builder.Services);
            builder.AddEntityFrameworkStores<DatabaseContext>();
            builder.AddSignInManager<SignInManager<AppUser>>();
            services.Configure<IdentityOptions>(options =>
            {
                // Default Password settings.
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 1;
                options.Password.RequiredUniqueChars = 0;
            });
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(opt =>
                {
                    opt.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Token:Key"])),
                        ValidIssuer = configuration["Token:Issuer"],
                        ValidateIssuer = true,
                        ValidateAudience = false
                    };
                });
            return services;
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Extensions\StartupServicesExtension.cs`:

```cs
﻿using Kitab.DataAccess;
using Kitab.DataAccess.IRepositories;
using Kitab.DataAccess.Repositories;
using Kitab.DataAccess.Services;
using Kitab.DataTransferObject;
using Kitab.Util.Errors;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;

namespace Kitab.API.Extensions
{
    public static class StartupServicesExtension
    {
        public static IServiceCollection AddStartupServices(this IServiceCollection services)
        {
            services.AddScoped<IUnitOfWork, UnitOfWork>();
            services.AddScoped<IResponseCacheService, ResponseCacheService>();
            services.AddScoped<IOrderService, OrderService>();
            services.AddScoped<IPaymentService, PaymentService>();
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IOrderRepository, OrderRepository>();
            services.AddScoped<IDeliveryModethodRepository, DeliveryMethodRepository>();
            services.AddScoped<IProductRepository, ProductRepository>();
            services.AddScoped<IBasketRepository, BasketRepository>();
            
            services.AddScoped(typeof(IBaseRepository<>), typeof(BaseRepository<>));
           
            services.AddTransient<IValidator<AddressDto>, AddressValidator>();
            services.AddTransient<IValidator<RegisterDto>, RegisterValidator>();
            services.AddTransient<IValidator<BasketDto>, BasketValidator>();
            services.AddTransient<IValidator<BasketItemDto>, BasketItemValidator>();

            services.Configure<ApiBehaviorOptions>(options =>
            {
                options.InvalidModelStateResponseFactory = actionContext =>
                {
                    var errors = actionContext.ModelState
                    .Where(a => a.Value.Errors.Count > 0)
                    .SelectMany(a => a.Value.Errors)
                    .Select(a => a.ErrorMessage).ToArray();
                    var errorResponse = new ApiValidationErrorResponse
                    {
                        Errors = errors
                    };
                    return new BadRequestObjectResult(errorResponse);
                };
            });
           
            return services;
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Extensions\SwaggerServiceExtension.cs`:

```cs
﻿using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
namespace Kitab.WebAPI.Extensions
{
    public static class SwaggerServiceExtension
    {
        public static IServiceCollection AddSwaggerDocumentation(this IServiceCollection services)
        {
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Kitab API", Version = "v1" });
                var securityScheme = new OpenApiSecurityScheme
                {
                    Description = "JWT Auth Bearer Token",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                };
                c.AddSecurityDefinition("Bearer", securityScheme);
                var securityRequirement = new OpenApiSecurityRequirement { { securityScheme, new[] { "Bearer" } } };
                c.AddSecurityRequirement(securityRequirement);
            });
            return services;
        }
        public static IApplicationBuilder UseSwaggerDocumentation(this IApplicationBuilder app)
        {
            app.UseSwagger();
            app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "Kitab API v1"); });
            return app;
        }
    }

}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Extensions\UserManagerExtension.cs`:

```cs
﻿using Kitab.DataAccess;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Kitab.Entities.AppUser;

namespace Kitab.WebAPI.Extensions
{
    public static class UserManagerExtension
    {
        public static async Task<AppUser> FindUserByClaimsPrincipleWithAddressAsync(this UserManager<AppUser> input, ClaimsPrincipal user)
        {
            var email = user.Claims?.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            // join dene
           var appUser= await input.Users.Include(a => a.Address).FirstOrDefaultAsync(a => a.Email == email);
            return appUser;
        }
        public static async Task<AppUser> FindByEmailFromClaimsPrincipalAsync(this UserManager<AppUser> input, ClaimsPrincipal user)
        {
            var email = user.Claims?.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            return await input.Users.SingleOrDefaultAsync(a => a.Email == email);
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\libman.json`:

```json
{
  "version": "1.0",
  "defaultProvider": "cdnjs",
  "libraries": []
}
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Kitab.WebAPI.csproj.nuget.dgspec.json`:

```json
{
  "format": 1,
  "restore": {
    "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj": {}
  },
  "projects": {
    "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj": {
      "version": "1.0.0",
      "restore": {
        "projectUniqueName": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj",
        "projectName": "Kitab.WebAPI",
        "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj",
        "packagesPath": "C:\\Users\\Morty\\.nuget\\packages\\",
        "outputPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\obj\\",
        "projectStyle": "PackageReference",
        "fallbackFolders": [
          "C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages"
        ],
        "configFilePaths": [
          "C:\\Users\\Morty\\AppData\\Roaming\\NuGet\\NuGet.Config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.FallbackLocation.config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.Offline.config"
        ],
        "originalTargetFrameworks": [
          "netcoreapp8.0"
        ],
        "sources": {
          "C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\": {},
          "C:\\Program Files\\dotnet\\library-packs": {},
          "https://api.nuget.org/v3/index.json": {}
        },
        "frameworks": {
          "net8.0": {
            "targetAlias": "netcoreapp8.0",
            "projectReferences": {
              "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj": {
                "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj"
              },
              "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj": {
                "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj"
              }
            }
          }
        },
        "warningProperties": {
          "warnAsError": [
            "NU1605"
          ]
        },
        "restoreAuditProperties": {
          "enableAudit": "true",
          "auditLevel": "low",
          "auditMode": "direct"
        }
      },
      "frameworks": {
        "net8.0": {
          "targetAlias": "netcoreapp8.0",
          "dependencies": {
            "Microsoft.AspNetCore.Authentication.JwtBearer": {
              "target": "Package",
              "version": "[8.0.10, )"
            },
            "Microsoft.EntityFrameworkCore.Sqlite": {
              "target": "Package",
              "version": "[8.0.10, )"
            },
            "Swashbuckle.AspNetCore.SwaggerGen": {
              "target": "Package",
              "version": "[6.9.0, )"
            },
            "Swashbuckle.AspNetCore.SwaggerUI": {
              "target": "Package",
              "version": "[6.9.0, )"
            }
          },
          "imports": [
            "net461",
            "net462",
            "net47",
            "net471",
            "net472",
            "net48",
            "net481"
          ],
          "assetTargetFallback": true,
          "warn": true,
          "frameworkReferences": {
            "Microsoft.AspNetCore.App": {
              "privateAssets": "none"
            },
            "Microsoft.NETCore.App": {
              "privateAssets": "all"
            }
          },
          "runtimeIdentifierGraphPath": "C:\\Program Files\\dotnet\\sdk\\8.0.403/PortableRuntimeIdentifierGraph.json"
        }
      }
    },
    "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj": {
      "version": "1.0.0",
      "restore": {
        "projectUniqueName": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj",
        "projectName": "Kitab.DataAccess",
        "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj",
        "packagesPath": "C:\\Users\\Morty\\.nuget\\packages\\",
        "outputPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\obj\\",
        "projectStyle": "PackageReference",
        "fallbackFolders": [
          "C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages"
        ],
        "configFilePaths": [
          "C:\\Users\\Morty\\AppData\\Roaming\\NuGet\\NuGet.Config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.FallbackLocation.config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.Offline.config"
        ],
        "originalTargetFrameworks": [
          "netcoreapp8.0"
        ],
        "sources": {
          "C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\": {},
          "C:\\Program Files\\dotnet\\library-packs": {},
          "https://api.nuget.org/v3/index.json": {}
        },
        "frameworks": {
          "net8.0": {
            "targetAlias": "netcoreapp8.0",
            "projectReferences": {
              "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\Kitab.Entities.csproj": {
                "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\Kitab.Entities.csproj"
              },
              "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj": {
                "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj"
              }
            }
          }
        },
        "warningProperties": {
          "warnAsError": [
            "NU1605"
          ]
        },
        "restoreAuditProperties": {
          "enableAudit": "true",
          "auditLevel": "low",
          "auditMode": "direct"
        }
      },
      "frameworks": {
        "net8.0": {
          "targetAlias": "netcoreapp8.0",
          "dependencies": {
            "Microsoft.AspNetCore.Identity.EntityFrameworkCore": {
              "target": "Package",
              "version": "[8.0.10, )"
            },
            "Microsoft.EntityFrameworkCore.Design": {
              "include": "Runtime, Build, Native, ContentFiles, Analyzers, BuildTransitive",
              "suppressParent": "All",
              "target": "Package",
              "version": "[8.0.10, )"
            },
            "Microsoft.EntityFrameworkCore.Sqlite": {
              "target": "Package",
              "version": "[8.0.10, )"
            },
            "Microsoft.EntityFrameworkCore.Tools": {
              "include": "Runtime, Build, Native, ContentFiles, Analyzers, BuildTransitive",
              "suppressParent": "All",
              "target": "Package",
              "version": "[8.0.10, )"
            },
            "Microsoft.IdentityModel.Tokens": {
              "target": "Package",
              "version": "[8.1.2, )"
            },
            "Stripe.net": {
              "target": "Package",
              "version": "[46.2.1, )"
            },
            "System.IdentityModel.Tokens.Jwt": {
              "target": "Package",
              "version": "[8.1.2, )"
            }
          },
          "imports": [
            "net461",
            "net462",
            "net47",
            "net471",
            "net472",
            "net48",
            "net481"
          ],
          "assetTargetFallback": true,
          "warn": true,
          "frameworkReferences": {
            "Microsoft.NETCore.App": {
              "privateAssets": "all"
            }
          },
          "runtimeIdentifierGraphPath": "C:\\Program Files\\dotnet\\sdk\\8.0.403/PortableRuntimeIdentifierGraph.json"
        }
      }
    },
    "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataTransferObject\\Kitab.DataTransferObject.csproj": {
      "version": "1.0.0",
      "restore": {
        "projectUniqueName": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataTransferObject\\Kitab.DataTransferObject.csproj",
        "projectName": "Kitab.DataTransferObject",
        "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataTransferObject\\Kitab.DataTransferObject.csproj",
        "packagesPath": "C:\\Users\\Morty\\.nuget\\packages\\",
        "outputPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataTransferObject\\obj\\",
        "projectStyle": "PackageReference",
        "fallbackFolders": [
          "C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages"
        ],
        "configFilePaths": [
          "C:\\Users\\Morty\\AppData\\Roaming\\NuGet\\NuGet.Config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.FallbackLocation.config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.Offline.config"
        ],
        "originalTargetFrameworks": [
          "netcoreapp8.0"
        ],
        "sources": {
          "C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\": {},
          "C:\\Program Files\\dotnet\\library-packs": {},
          "https://api.nuget.org/v3/index.json": {}
        },
        "frameworks": {
          "net8.0": {
            "targetAlias": "netcoreapp8.0",
            "projectReferences": {}
          }
        },
        "warningProperties": {
          "warnAsError": [
            "NU1605"
          ]
        },
        "restoreAuditProperties": {
          "enableAudit": "true",
          "auditLevel": "low",
          "auditMode": "direct"
        }
      },
      "frameworks": {
        "net8.0": {
          "targetAlias": "netcoreapp8.0",
          "dependencies": {
            "FluentValidation": {
              "target": "Package",
              "version": "[11.10.0, )"
            }
          },
          "imports": [
            "net461",
            "net462",
            "net47",
            "net471",
            "net472",
            "net48",
            "net481"
          ],
          "assetTargetFallback": true,
          "warn": true,
          "frameworkReferences": {
            "Microsoft.NETCore.App": {
              "privateAssets": "all"
            }
          },
          "runtimeIdentifierGraphPath": "C:\\Program Files\\dotnet\\sdk\\8.0.403/PortableRuntimeIdentifierGraph.json"
        }
      }
    },
    "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\Kitab.Entities.csproj": {
      "version": "1.0.0",
      "restore": {
        "projectUniqueName": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\Kitab.Entities.csproj",
        "projectName": "Kitab.Entities",
        "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\Kitab.Entities.csproj",
        "packagesPath": "C:\\Users\\Morty\\.nuget\\packages\\",
        "outputPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\obj\\",
        "projectStyle": "PackageReference",
        "fallbackFolders": [
          "C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages"
        ],
        "configFilePaths": [
          "C:\\Users\\Morty\\AppData\\Roaming\\NuGet\\NuGet.Config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.FallbackLocation.config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.Offline.config"
        ],
        "originalTargetFrameworks": [
          "netcoreapp8.0"
        ],
        "sources": {
          "C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\": {},
          "C:\\Program Files\\dotnet\\library-packs": {},
          "https://api.nuget.org/v3/index.json": {}
        },
        "frameworks": {
          "net8.0": {
            "targetAlias": "netcoreapp8.0",
            "projectReferences": {}
          }
        },
        "warningProperties": {
          "warnAsError": [
            "NU1605"
          ]
        },
        "restoreAuditProperties": {
          "enableAudit": "true",
          "auditLevel": "low",
          "auditMode": "direct"
        }
      },
      "frameworks": {
        "net8.0": {
          "targetAlias": "netcoreapp8.0",
          "dependencies": {
            "Microsoft.Extensions.Identity.Stores": {
              "target": "Package",
              "version": "[8.0.10, )"
            }
          },
          "imports": [
            "net461",
            "net462",
            "net47",
            "net471",
            "net472",
            "net48",
            "net481"
          ],
          "assetTargetFallback": true,
          "warn": true,
          "frameworkReferences": {
            "Microsoft.NETCore.App": {
              "privateAssets": "all"
            }
          },
          "runtimeIdentifierGraphPath": "C:\\Program Files\\dotnet\\sdk\\8.0.403/PortableRuntimeIdentifierGraph.json"
        }
      }
    },
    "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj": {
      "version": "1.0.0",
      "restore": {
        "projectUniqueName": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj",
        "projectName": "Kitab.Util",
        "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj",
        "packagesPath": "C:\\Users\\Morty\\.nuget\\packages\\",
        "outputPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\obj\\",
        "projectStyle": "PackageReference",
        "fallbackFolders": [
          "C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages"
        ],
        "configFilePaths": [
          "C:\\Users\\Morty\\AppData\\Roaming\\NuGet\\NuGet.Config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.FallbackLocation.config",
          "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.Offline.config"
        ],
        "originalTargetFrameworks": [
          "netcoreapp8.0"
        ],
        "sources": {
          "C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\": {},
          "C:\\Program Files\\dotnet\\library-packs": {},
          "https://api.nuget.org/v3/index.json": {}
        },
        "frameworks": {
          "net8.0": {
            "targetAlias": "netcoreapp8.0",
            "projectReferences": {
              "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataTransferObject\\Kitab.DataTransferObject.csproj": {
                "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataTransferObject\\Kitab.DataTransferObject.csproj"
              },
              "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\Kitab.Entities.csproj": {
                "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Entities\\Kitab.Entities.csproj"
              }
            }
          }
        },
        "warningProperties": {
          "warnAsError": [
            "NU1605"
          ]
        },
        "restoreAuditProperties": {
          "enableAudit": "true",
          "auditLevel": "low",
          "auditMode": "direct"
        }
      },
      "frameworks": {
        "net8.0": {
          "targetAlias": "netcoreapp8.0",
          "dependencies": {
            "AutoMapper": {
              "target": "Package",
              "version": "[13.0.1, )"
            },
            "StackExchange.Redis": {
              "target": "Package",
              "version": "[2.8.16, )"
            },
            "Stripe.net": {
              "target": "Package",
              "version": "[46.2.1, )"
            },
            "Swashbuckle.AspNetCore": {
              "target": "Package",
              "version": "[6.9.0, )"
            }
          },
          "imports": [
            "net461",
            "net462",
            "net47",
            "net471",
            "net472",
            "net48",
            "net481"
          ],
          "assetTargetFallback": true,
          "warn": true,
          "frameworkReferences": {
            "Microsoft.NETCore.App": {
              "privateAssets": "all"
            }
          },
          "runtimeIdentifierGraphPath": "C:\\Program Files\\dotnet\\sdk\\8.0.403/PortableRuntimeIdentifierGraph.json"
        }
      }
    }
  }
}
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Kitab.WebAPI.csproj.nuget.g.props`:

```props
﻿<?xml version="1.0" encoding="utf-8" standalone="no"?>
<Project ToolsVersion="14.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup Condition=" '$(ExcludeRestorePackageImports)' != 'true' ">
    <RestoreSuccess Condition=" '$(RestoreSuccess)' == '' ">True</RestoreSuccess>
    <RestoreTool Condition=" '$(RestoreTool)' == '' ">NuGet</RestoreTool>
    <ProjectAssetsFile Condition=" '$(ProjectAssetsFile)' == '' ">$(MSBuildThisFileDirectory)project.assets.json</ProjectAssetsFile>
    <NuGetPackageRoot Condition=" '$(NuGetPackageRoot)' == '' ">$(UserProfile)\.nuget\packages\</NuGetPackageRoot>
    <NuGetPackageFolders Condition=" '$(NuGetPackageFolders)' == '' ">C:\Users\Morty\.nuget\packages\;C:\Program Files (x86)\Microsoft Visual Studio\Shared\NuGetPackages</NuGetPackageFolders>
    <NuGetProjectStyle Condition=" '$(NuGetProjectStyle)' == '' ">PackageReference</NuGetProjectStyle>
    <NuGetToolVersion Condition=" '$(NuGetToolVersion)' == '' ">6.11.1</NuGetToolVersion>
  </PropertyGroup>
  <ItemGroup Condition=" '$(ExcludeRestorePackageImports)' != 'true' ">
    <SourceRoot Include="C:\Users\Morty\.nuget\packages\" />
    <SourceRoot Include="C:\Program Files (x86)\Microsoft Visual Studio\Shared\NuGetPackages\" />
  </ItemGroup>
  <ImportGroup Condition=" '$(ExcludeRestorePackageImports)' != 'true' ">
    <Import Project="$(NuGetPackageRoot)microsoft.entityframeworkcore\8.0.10\buildTransitive\net8.0\Microsoft.EntityFrameworkCore.props" Condition="Exists('$(NuGetPackageRoot)microsoft.entityframeworkcore\8.0.10\buildTransitive\net8.0\Microsoft.EntityFrameworkCore.props')" />
  </ImportGroup>
  <PropertyGroup Condition=" '$(ExcludeRestorePackageImports)' != 'true' ">
    <PkgMicrosoft_Extensions_ApiDescription_Server Condition=" '$(PkgMicrosoft_Extensions_ApiDescription_Server)' == '' ">C:\Users\Morty\.nuget\packages\microsoft.extensions.apidescription.server\6.0.5</PkgMicrosoft_Extensions_ApiDescription_Server>
  </PropertyGroup>
</Project>
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Kitab.WebAPI.csproj.nuget.g.targets`:

```targets
﻿<?xml version="1.0" encoding="utf-8" standalone="no"?>
<Project ToolsVersion="14.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ImportGroup Condition=" '$(ExcludeRestorePackageImports)' != 'true' ">
    <Import Project="$(NuGetPackageRoot)microsoft.extensions.logging.abstractions\8.0.2\buildTransitive\net6.0\Microsoft.Extensions.Logging.Abstractions.targets" Condition="Exists('$(NuGetPackageRoot)microsoft.extensions.logging.abstractions\8.0.2\buildTransitive\net6.0\Microsoft.Extensions.Logging.Abstractions.targets')" />
    <Import Project="$(NuGetPackageRoot)sqlitepclraw.lib.e_sqlite3\2.1.6\buildTransitive\net8.0\SQLitePCLRaw.lib.e_sqlite3.targets" Condition="Exists('$(NuGetPackageRoot)sqlitepclraw.lib.e_sqlite3\2.1.6\buildTransitive\net8.0\SQLitePCLRaw.lib.e_sqlite3.targets')" />
    <Import Project="$(NuGetPackageRoot)microsoft.extensions.options\8.0.2\buildTransitive\net6.0\Microsoft.Extensions.Options.targets" Condition="Exists('$(NuGetPackageRoot)microsoft.extensions.options\8.0.2\buildTransitive\net6.0\Microsoft.Extensions.Options.targets')" />
  </ImportGroup>
</Project>
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Debug\netcoreapp8.0\Kitab.WebAPI.AssemblyInfo.cs`:

```cs
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

using System;
using System.Reflection;

[assembly: System.Reflection.AssemblyCompanyAttribute("Kitab.WebAPI")]
[assembly: System.Reflection.AssemblyConfigurationAttribute("Debug")]
[assembly: System.Reflection.AssemblyFileVersionAttribute("1.0.0.0")]
[assembly: System.Reflection.AssemblyInformationalVersionAttribute("1.0.0")]
[assembly: System.Reflection.AssemblyProductAttribute("Kitab.WebAPI")]
[assembly: System.Reflection.AssemblyTitleAttribute("Kitab.WebAPI")]
[assembly: System.Reflection.AssemblyVersionAttribute("1.0.0.0")]

// Generated by the MSBuild WriteCodeFragment class.


```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Debug\netcoreapp8.0\Kitab.WebAPI.AssemblyInfoInputs.cache`:

```cache
43ab5bf32e26641f69861b887f9cd9ce40cfadabb94443e69cbde53edd72e6ea

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Debug\netcoreapp8.0\Kitab.WebAPI.GeneratedMSBuildEditorConfig.editorconfig`:

```editorconfig
is_global = true
build_property.TargetFramework = netcoreapp8.0
build_property.TargetPlatformMinVersion = 
build_property.UsingMicrosoftNETSdkWeb = true
build_property.ProjectTypeGuids = 
build_property.InvariantGlobalization = 
build_property.PlatformNeutralAssembly = 
build_property.EnforceExtendedAnalyzerRules = 
build_property._SupportedPlatformList = Linux,macOS,Windows
build_property.RootNamespace = Kitab.WebAPI
build_property.RootNamespace = Kitab.WebAPI
build_property.ProjectDir = C:\Users\Morty\Desktop\Kitab-master\Kitab.API\
build_property.EnableComHosting = 
build_property.EnableGeneratedComInterfaceComImportInterop = 
build_property.RazorLangVersion = 8.0
build_property.SupportLocalizedComponentNames = 
build_property.GenerateRazorMetadataSourceChecksumAttributes = 
build_property.MSBuildProjectDirectory = C:\Users\Morty\Desktop\Kitab-master\Kitab.API
build_property._RazorSourceGeneratorDebug = 

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\project.assets.json`:

```json
{
  "version": 3,
  "targets": {
    "net8.0": {
      "AutoMapper/13.0.1": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.Options": "6.0.0"
        },
        "compile": {
          "lib/net6.0/AutoMapper.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net6.0/AutoMapper.dll": {
            "related": ".xml"
          }
        }
      },
      "FluentValidation/11.10.0": {
        "type": "package",
        "compile": {
          "lib/net8.0/FluentValidation.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/FluentValidation.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.AspNetCore.Authentication.JwtBearer/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.IdentityModel.Protocols.OpenIdConnect": "7.1.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.AspNetCore.Authentication.JwtBearer.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.AspNetCore.Authentication.JwtBearer.dll": {
            "related": ".xml"
          }
        },
        "frameworkReferences": [
          "Microsoft.AspNetCore.App"
        ]
      },
      "Microsoft.AspNetCore.Cryptography.Internal/8.0.10": {
        "type": "package",
        "compile": {
          "lib/net8.0/Microsoft.AspNetCore.Cryptography.Internal.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.AspNetCore.Cryptography.Internal.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.AspNetCore.Cryptography.KeyDerivation/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.AspNetCore.Cryptography.Internal": "8.0.10"
        },
        "compile": {
          "lib/net8.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.AspNetCore.Identity.EntityFrameworkCore/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.EntityFrameworkCore.Relational": "8.0.10",
          "Microsoft.Extensions.Identity.Stores": "8.0.10"
        },
        "compile": {
          "lib/net8.0/Microsoft.AspNetCore.Identity.EntityFrameworkCore.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.AspNetCore.Identity.EntityFrameworkCore.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.Bcl.TimeProvider/8.0.1": {
        "type": "package",
        "compile": {
          "lib/net8.0/Microsoft.Bcl.TimeProvider.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Bcl.TimeProvider.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Data.Sqlite.Core/8.0.10": {
        "type": "package",
        "dependencies": {
          "SQLitePCLRaw.core": "2.1.6"
        },
        "compile": {
          "lib/net8.0/Microsoft.Data.Sqlite.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Data.Sqlite.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.EntityFrameworkCore/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.EntityFrameworkCore.Abstractions": "8.0.10",
          "Microsoft.EntityFrameworkCore.Analyzers": "8.0.10",
          "Microsoft.Extensions.Caching.Memory": "8.0.1",
          "Microsoft.Extensions.Logging": "8.0.1"
        },
        "compile": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net8.0/Microsoft.EntityFrameworkCore.props": {}
        }
      },
      "Microsoft.EntityFrameworkCore.Abstractions/8.0.10": {
        "type": "package",
        "compile": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.Abstractions.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.EntityFrameworkCore.Analyzers/8.0.10": {
        "type": "package",
        "compile": {
          "lib/netstandard2.0/_._": {}
        },
        "runtime": {
          "lib/netstandard2.0/_._": {}
        }
      },
      "Microsoft.EntityFrameworkCore.Relational/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.EntityFrameworkCore": "8.0.10",
          "Microsoft.Extensions.Configuration.Abstractions": "8.0.0"
        },
        "compile": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.Relational.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.Relational.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.EntityFrameworkCore.Sqlite/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.EntityFrameworkCore.Sqlite.Core": "8.0.10",
          "SQLitePCLRaw.bundle_e_sqlite3": "2.1.6"
        },
        "compile": {
          "lib/net8.0/_._": {}
        },
        "runtime": {
          "lib/net8.0/_._": {}
        }
      },
      "Microsoft.EntityFrameworkCore.Sqlite.Core/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.Data.Sqlite.Core": "8.0.10",
          "Microsoft.EntityFrameworkCore.Relational": "8.0.10",
          "Microsoft.Extensions.DependencyModel": "8.0.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.Sqlite.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.EntityFrameworkCore.Sqlite.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.Extensions.ApiDescription.Server/6.0.5": {
        "type": "package",
        "build": {
          "build/_._": {}
        },
        "buildMultiTargeting": {
          "buildMultiTargeting/_._": {}
        }
      },
      "Microsoft.Extensions.Caching.Abstractions/8.0.0": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.Primitives": "8.0.0"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Caching.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Caching.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Extensions.Caching.Memory/8.0.1": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.Caching.Abstractions": "8.0.0",
          "Microsoft.Extensions.DependencyInjection.Abstractions": "8.0.2",
          "Microsoft.Extensions.Logging.Abstractions": "8.0.2",
          "Microsoft.Extensions.Options": "8.0.2",
          "Microsoft.Extensions.Primitives": "8.0.0"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Caching.Memory.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Caching.Memory.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Extensions.Configuration.Abstractions/8.0.0": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.Primitives": "8.0.0"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Configuration.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Configuration.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Extensions.DependencyInjection/8.0.1": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "8.0.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.DependencyInjection.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.DependencyInjection.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Extensions.DependencyInjection.Abstractions/8.0.2": {
        "type": "package",
        "compile": {
          "lib/net8.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Extensions.DependencyModel/8.0.2": {
        "type": "package",
        "compile": {
          "lib/net8.0/Microsoft.Extensions.DependencyModel.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.DependencyModel.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Extensions.Identity.Core/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.AspNetCore.Cryptography.KeyDerivation": "8.0.10",
          "Microsoft.Extensions.Logging": "8.0.1",
          "Microsoft.Extensions.Options": "8.0.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Identity.Core.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Identity.Core.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.Extensions.Identity.Stores/8.0.10": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.Caching.Abstractions": "8.0.0",
          "Microsoft.Extensions.Identity.Core": "8.0.10",
          "Microsoft.Extensions.Logging": "8.0.1"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Identity.Stores.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Identity.Stores.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.Extensions.Logging/8.0.1": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection": "8.0.1",
          "Microsoft.Extensions.Logging.Abstractions": "8.0.2",
          "Microsoft.Extensions.Options": "8.0.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Logging.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Logging.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.Extensions.Logging.Abstractions/8.0.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "8.0.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Logging.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Logging.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/Microsoft.Extensions.Logging.Abstractions.targets": {}
        }
      },
      "Microsoft.Extensions.Options/8.0.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "8.0.0",
          "Microsoft.Extensions.Primitives": "8.0.0"
        },
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Options.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Options.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/Microsoft.Extensions.Options.targets": {}
        }
      },
      "Microsoft.Extensions.Primitives/8.0.0": {
        "type": "package",
        "compile": {
          "lib/net8.0/Microsoft.Extensions.Primitives.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.Extensions.Primitives.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Microsoft.IdentityModel.Abstractions/8.1.2": {
        "type": "package",
        "compile": {
          "lib/net8.0/Microsoft.IdentityModel.Abstractions.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.IdentityModel.Abstractions.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.IdentityModel.JsonWebTokens/8.1.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.Bcl.TimeProvider": "8.0.1",
          "Microsoft.IdentityModel.Tokens": "8.1.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.IdentityModel.JsonWebTokens.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.IdentityModel.JsonWebTokens.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.IdentityModel.Logging/8.1.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.IdentityModel.Abstractions": "8.1.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.IdentityModel.Logging.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.IdentityModel.Logging.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.IdentityModel.Protocols/7.1.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.IdentityModel.Logging": "7.1.2",
          "Microsoft.IdentityModel.Tokens": "7.1.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.IdentityModel.Protocols.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.IdentityModel.Protocols.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.IdentityModel.Protocols.OpenIdConnect/7.1.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.IdentityModel.Protocols": "7.1.2",
          "System.IdentityModel.Tokens.Jwt": "7.1.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.IdentityModel.Tokens/8.1.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.Bcl.TimeProvider": "8.0.1",
          "Microsoft.IdentityModel.Logging": "8.1.2"
        },
        "compile": {
          "lib/net8.0/Microsoft.IdentityModel.Tokens.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Microsoft.IdentityModel.Tokens.dll": {
            "related": ".xml"
          }
        }
      },
      "Microsoft.OpenApi/1.6.14": {
        "type": "package",
        "compile": {
          "lib/netstandard2.0/Microsoft.OpenApi.dll": {
            "related": ".pdb;.xml"
          }
        },
        "runtime": {
          "lib/netstandard2.0/Microsoft.OpenApi.dll": {
            "related": ".pdb;.xml"
          }
        }
      },
      "Newtonsoft.Json/13.0.3": {
        "type": "package",
        "compile": {
          "lib/net6.0/Newtonsoft.Json.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net6.0/Newtonsoft.Json.dll": {
            "related": ".xml"
          }
        }
      },
      "Pipelines.Sockets.Unofficial/2.2.8": {
        "type": "package",
        "dependencies": {
          "System.IO.Pipelines": "5.0.1"
        },
        "compile": {
          "lib/net5.0/Pipelines.Sockets.Unofficial.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net5.0/Pipelines.Sockets.Unofficial.dll": {
            "related": ".xml"
          }
        }
      },
      "SQLitePCLRaw.bundle_e_sqlite3/2.1.6": {
        "type": "package",
        "dependencies": {
          "SQLitePCLRaw.lib.e_sqlite3": "2.1.6",
          "SQLitePCLRaw.provider.e_sqlite3": "2.1.6"
        },
        "compile": {
          "lib/netstandard2.0/SQLitePCLRaw.batteries_v2.dll": {}
        },
        "runtime": {
          "lib/netstandard2.0/SQLitePCLRaw.batteries_v2.dll": {}
        }
      },
      "SQLitePCLRaw.core/2.1.6": {
        "type": "package",
        "dependencies": {
          "System.Memory": "4.5.3"
        },
        "compile": {
          "lib/netstandard2.0/SQLitePCLRaw.core.dll": {}
        },
        "runtime": {
          "lib/netstandard2.0/SQLitePCLRaw.core.dll": {}
        }
      },
      "SQLitePCLRaw.lib.e_sqlite3/2.1.6": {
        "type": "package",
        "compile": {
          "lib/netstandard2.0/_._": {}
        },
        "runtime": {
          "lib/netstandard2.0/_._": {}
        },
        "build": {
          "buildTransitive/net8.0/SQLitePCLRaw.lib.e_sqlite3.targets": {}
        },
        "runtimeTargets": {
          "runtimes/browser-wasm/nativeassets/net8.0/e_sqlite3.a": {
            "assetType": "native",
            "rid": "browser-wasm"
          },
          "runtimes/linux-arm/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-arm"
          },
          "runtimes/linux-arm64/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-arm64"
          },
          "runtimes/linux-armel/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-armel"
          },
          "runtimes/linux-mips64/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-mips64"
          },
          "runtimes/linux-musl-arm/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-musl-arm"
          },
          "runtimes/linux-musl-arm64/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-musl-arm64"
          },
          "runtimes/linux-musl-x64/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-musl-x64"
          },
          "runtimes/linux-ppc64le/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-ppc64le"
          },
          "runtimes/linux-s390x/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-s390x"
          },
          "runtimes/linux-x64/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-x64"
          },
          "runtimes/linux-x86/native/libe_sqlite3.so": {
            "assetType": "native",
            "rid": "linux-x86"
          },
          "runtimes/maccatalyst-arm64/native/libe_sqlite3.dylib": {
            "assetType": "native",
            "rid": "maccatalyst-arm64"
          },
          "runtimes/maccatalyst-x64/native/libe_sqlite3.dylib": {
            "assetType": "native",
            "rid": "maccatalyst-x64"
          },
          "runtimes/osx-arm64/native/libe_sqlite3.dylib": {
            "assetType": "native",
            "rid": "osx-arm64"
          },
          "runtimes/osx-x64/native/libe_sqlite3.dylib": {
            "assetType": "native",
            "rid": "osx-x64"
          },
          "runtimes/win-arm/native/e_sqlite3.dll": {
            "assetType": "native",
            "rid": "win-arm"
          },
          "runtimes/win-arm64/native/e_sqlite3.dll": {
            "assetType": "native",
            "rid": "win-arm64"
          },
          "runtimes/win-x64/native/e_sqlite3.dll": {
            "assetType": "native",
            "rid": "win-x64"
          },
          "runtimes/win-x86/native/e_sqlite3.dll": {
            "assetType": "native",
            "rid": "win-x86"
          }
        }
      },
      "SQLitePCLRaw.provider.e_sqlite3/2.1.6": {
        "type": "package",
        "dependencies": {
          "SQLitePCLRaw.core": "2.1.6"
        },
        "compile": {
          "lib/net6.0/SQLitePCLRaw.provider.e_sqlite3.dll": {}
        },
        "runtime": {
          "lib/net6.0/SQLitePCLRaw.provider.e_sqlite3.dll": {}
        }
      },
      "StackExchange.Redis/2.8.16": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.Logging.Abstractions": "6.0.0",
          "Pipelines.Sockets.Unofficial": "2.2.8"
        },
        "compile": {
          "lib/net6.0/StackExchange.Redis.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net6.0/StackExchange.Redis.dll": {
            "related": ".xml"
          }
        }
      },
      "Stripe.net/46.2.1": {
        "type": "package",
        "dependencies": {
          "Newtonsoft.Json": "13.0.3",
          "System.Configuration.ConfigurationManager": "8.0.0"
        },
        "compile": {
          "lib/net8.0/Stripe.net.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/Stripe.net.dll": {
            "related": ".xml"
          }
        }
      },
      "Swashbuckle.AspNetCore/6.9.0": {
        "type": "package",
        "dependencies": {
          "Microsoft.Extensions.ApiDescription.Server": "6.0.5",
          "Swashbuckle.AspNetCore.Swagger": "6.9.0",
          "Swashbuckle.AspNetCore.SwaggerGen": "6.9.0",
          "Swashbuckle.AspNetCore.SwaggerUI": "6.9.0"
        },
        "build": {
          "build/_._": {}
        },
        "buildMultiTargeting": {
          "buildMultiTargeting/_._": {}
        }
      },
      "Swashbuckle.AspNetCore.Swagger/6.9.0": {
        "type": "package",
        "dependencies": {
          "Microsoft.OpenApi": "1.6.14"
        },
        "compile": {
          "lib/net8.0/Swashbuckle.AspNetCore.Swagger.dll": {
            "related": ".pdb;.xml"
          }
        },
        "runtime": {
          "lib/net8.0/Swashbuckle.AspNetCore.Swagger.dll": {
            "related": ".pdb;.xml"
          }
        },
        "frameworkReferences": [
          "Microsoft.AspNetCore.App"
        ]
      },
      "Swashbuckle.AspNetCore.SwaggerGen/6.9.0": {
        "type": "package",
        "dependencies": {
          "Swashbuckle.AspNetCore.Swagger": "6.9.0"
        },
        "compile": {
          "lib/net8.0/Swashbuckle.AspNetCore.SwaggerGen.dll": {
            "related": ".pdb;.xml"
          }
        },
        "runtime": {
          "lib/net8.0/Swashbuckle.AspNetCore.SwaggerGen.dll": {
            "related": ".pdb;.xml"
          }
        }
      },
      "Swashbuckle.AspNetCore.SwaggerUI/6.9.0": {
        "type": "package",
        "compile": {
          "lib/net8.0/Swashbuckle.AspNetCore.SwaggerUI.dll": {
            "related": ".pdb;.xml"
          }
        },
        "runtime": {
          "lib/net8.0/Swashbuckle.AspNetCore.SwaggerUI.dll": {
            "related": ".pdb;.xml"
          }
        },
        "frameworkReferences": [
          "Microsoft.AspNetCore.App"
        ]
      },
      "System.Configuration.ConfigurationManager/8.0.0": {
        "type": "package",
        "dependencies": {
          "System.Diagnostics.EventLog": "8.0.0",
          "System.Security.Cryptography.ProtectedData": "8.0.0"
        },
        "compile": {
          "lib/net8.0/System.Configuration.ConfigurationManager.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/System.Configuration.ConfigurationManager.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "System.Diagnostics.EventLog/8.0.0": {
        "type": "package",
        "compile": {
          "lib/net8.0/System.Diagnostics.EventLog.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/System.Diagnostics.EventLog.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        },
        "runtimeTargets": {
          "runtimes/win/lib/net8.0/System.Diagnostics.EventLog.Messages.dll": {
            "assetType": "runtime",
            "rid": "win"
          },
          "runtimes/win/lib/net8.0/System.Diagnostics.EventLog.dll": {
            "assetType": "runtime",
            "rid": "win"
          }
        }
      },
      "System.IdentityModel.Tokens.Jwt/8.1.2": {
        "type": "package",
        "dependencies": {
          "Microsoft.IdentityModel.JsonWebTokens": "8.1.2",
          "Microsoft.IdentityModel.Tokens": "8.1.2"
        },
        "compile": {
          "lib/net8.0/System.IdentityModel.Tokens.Jwt.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/System.IdentityModel.Tokens.Jwt.dll": {
            "related": ".xml"
          }
        }
      },
      "System.IO.Pipelines/5.0.1": {
        "type": "package",
        "compile": {
          "ref/netcoreapp2.0/System.IO.Pipelines.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/netcoreapp3.0/System.IO.Pipelines.dll": {
            "related": ".xml"
          }
        }
      },
      "System.Memory/4.5.3": {
        "type": "package",
        "compile": {
          "ref/netcoreapp2.1/_._": {}
        },
        "runtime": {
          "lib/netcoreapp2.1/_._": {}
        }
      },
      "System.Security.Cryptography.ProtectedData/8.0.0": {
        "type": "package",
        "compile": {
          "lib/net8.0/System.Security.Cryptography.ProtectedData.dll": {
            "related": ".xml"
          }
        },
        "runtime": {
          "lib/net8.0/System.Security.Cryptography.ProtectedData.dll": {
            "related": ".xml"
          }
        },
        "build": {
          "buildTransitive/net6.0/_._": {}
        }
      },
      "Kitab.DataAccess/1.0.0": {
        "type": "project",
        "framework": ".NETCoreApp,Version=v8.0",
        "dependencies": {
          "Kitab.Entities": "1.0.0",
          "Kitab.Util": "1.0.0",
          "Microsoft.AspNetCore.Identity.EntityFrameworkCore": "8.0.10",
          "Microsoft.EntityFrameworkCore.Sqlite": "8.0.10",
          "Microsoft.IdentityModel.Tokens": "8.1.2",
          "Stripe.net": "46.2.1",
          "System.IdentityModel.Tokens.Jwt": "8.1.2"
        },
        "compile": {
          "bin/placeholder/Kitab.DataAccess.dll": {}
        },
        "runtime": {
          "bin/placeholder/Kitab.DataAccess.dll": {}
        }
      },
      "Kitab.DataTransferObject/1.0.0": {
        "type": "project",
        "framework": ".NETCoreApp,Version=v8.0",
        "dependencies": {
          "FluentValidation": "11.10.0"
        },
        "compile": {
          "bin/placeholder/Kitab.DataTransferObject.dll": {}
        },
        "runtime": {
          "bin/placeholder/Kitab.DataTransferObject.dll": {}
        }
      },
      "Kitab.Entities/1.0.0": {
        "type": "project",
        "framework": ".NETCoreApp,Version=v8.0",
        "dependencies": {
          "Microsoft.Extensions.Identity.Stores": "8.0.10"
        },
        "compile": {
          "bin/placeholder/Kitab.Entities.dll": {}
        },
        "runtime": {
          "bin/placeholder/Kitab.Entities.dll": {}
        }
      },
      "Kitab.Util/1.0.0": {
        "type": "project",
        "framework": ".NETCoreApp,Version=v8.0",
        "dependencies": {
          "AutoMapper": "13.0.1",
          "Kitab.DataTransferObject": "1.0.0",
          "Kitab.Entities": "1.0.0",
          "StackExchange.Redis": "2.8.16",
          "Stripe.net": "46.2.1",
          "Swashbuckle.AspNetCore": "6.9.0"
        },
        "compile": {
          "bin/placeholder/Kitab.Util.dll": {}
        },
        "runtime": {
          "bin/placeholder/Kitab.Util.dll": {}
        }
      }
    }
  },
  "libraries": {
    "AutoMapper/13.0.1": {
      "sha512": "/Fx1SbJ16qS7dU4i604Sle+U9VLX+WSNVJggk6MupKVkYvvBm4XqYaeFuf67diHefHKHs50uQIS2YEDFhPCakQ==",
      "type": "package",
      "path": "automapper/13.0.1",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "automapper.13.0.1.nupkg.sha512",
        "automapper.nuspec",
        "icon.png",
        "lib/net6.0/AutoMapper.dll",
        "lib/net6.0/AutoMapper.xml"
      ]
    },
    "FluentValidation/11.10.0": {
      "sha512": "qsJGSJDdZ8qiG+lVJ70PZfJHcEdq8UQZ/tZDXoj78/iHKG6lVKtMJsD11zyyv/IPc7rwqGqnFoFLTNzpo3IPYg==",
      "type": "package",
      "path": "fluentvalidation/11.10.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "fluent-validation-icon.png",
        "fluentvalidation.11.10.0.nupkg.sha512",
        "fluentvalidation.nuspec",
        "lib/net5.0/FluentValidation.dll",
        "lib/net5.0/FluentValidation.xml",
        "lib/net6.0/FluentValidation.dll",
        "lib/net6.0/FluentValidation.xml",
        "lib/net7.0/FluentValidation.dll",
        "lib/net7.0/FluentValidation.xml",
        "lib/net8.0/FluentValidation.dll",
        "lib/net8.0/FluentValidation.xml",
        "lib/netstandard2.0/FluentValidation.dll",
        "lib/netstandard2.0/FluentValidation.xml",
        "lib/netstandard2.1/FluentValidation.dll",
        "lib/netstandard2.1/FluentValidation.xml"
      ]
    },
    "Microsoft.AspNetCore.Authentication.JwtBearer/8.0.10": {
      "sha512": "rcPXghZCc82IB9U2Px1Ln5Zn3vjV4p83H/Few5T/904hBddjSz03COQ2zOGWBBvdTBY+GciAUJwgBFNWaxLfqw==",
      "type": "package",
      "path": "microsoft.aspnetcore.authentication.jwtbearer/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/net8.0/Microsoft.AspNetCore.Authentication.JwtBearer.dll",
        "lib/net8.0/Microsoft.AspNetCore.Authentication.JwtBearer.xml",
        "microsoft.aspnetcore.authentication.jwtbearer.8.0.10.nupkg.sha512",
        "microsoft.aspnetcore.authentication.jwtbearer.nuspec"
      ]
    },
    "Microsoft.AspNetCore.Cryptography.Internal/8.0.10": {
      "sha512": "MT/jvNoiXUB82drzqtqZqyAfxQH2b0kpEyjjMYrSLmqgAvBkMEKJelbqHazEo5Lxtq43uquPgeBtTuSrVog5lQ==",
      "type": "package",
      "path": "microsoft.aspnetcore.cryptography.internal/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/net462/Microsoft.AspNetCore.Cryptography.Internal.dll",
        "lib/net462/Microsoft.AspNetCore.Cryptography.Internal.xml",
        "lib/net8.0/Microsoft.AspNetCore.Cryptography.Internal.dll",
        "lib/net8.0/Microsoft.AspNetCore.Cryptography.Internal.xml",
        "lib/netstandard2.0/Microsoft.AspNetCore.Cryptography.Internal.dll",
        "lib/netstandard2.0/Microsoft.AspNetCore.Cryptography.Internal.xml",
        "microsoft.aspnetcore.cryptography.internal.8.0.10.nupkg.sha512",
        "microsoft.aspnetcore.cryptography.internal.nuspec"
      ]
    },
    "Microsoft.AspNetCore.Cryptography.KeyDerivation/8.0.10": {
      "sha512": "4jd0g3k2R1L1bhhpVmJOp7rAs76V9XLVuhl8J3sTAcl2dKMS78PsKG1HX75U73WEEwrsM4Bui2/N1/Blwgt5iw==",
      "type": "package",
      "path": "microsoft.aspnetcore.cryptography.keyderivation/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/net462/Microsoft.AspNetCore.Cryptography.KeyDerivation.dll",
        "lib/net462/Microsoft.AspNetCore.Cryptography.KeyDerivation.xml",
        "lib/net8.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.dll",
        "lib/net8.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.xml",
        "lib/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.dll",
        "lib/netstandard2.0/Microsoft.AspNetCore.Cryptography.KeyDerivation.xml",
        "microsoft.aspnetcore.cryptography.keyderivation.8.0.10.nupkg.sha512",
        "microsoft.aspnetcore.cryptography.keyderivation.nuspec"
      ]
    },
    "Microsoft.AspNetCore.Identity.EntityFrameworkCore/8.0.10": {
      "sha512": "vMeY9F3Sq+AiZlquf84rwHOAQBS8nb8kd1RcuoXKPBhHNGBxMLYnr8/e/FCwu7kb14hH/rqWoEuyO4WXpAO6Rw==",
      "type": "package",
      "path": "microsoft.aspnetcore.identity.entityframeworkcore/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/net8.0/Microsoft.AspNetCore.Identity.EntityFrameworkCore.dll",
        "lib/net8.0/Microsoft.AspNetCore.Identity.EntityFrameworkCore.xml",
        "microsoft.aspnetcore.identity.entityframeworkcore.8.0.10.nupkg.sha512",
        "microsoft.aspnetcore.identity.entityframeworkcore.nuspec"
      ]
    },
    "Microsoft.Bcl.TimeProvider/8.0.1": {
      "sha512": "C7kWHJnMRY7EvJev2S8+yJHZ1y7A4ZlLbA4NE+O23BDIAN5mHeqND1m+SKv1ChRS5YlCDW7yAMUe7lttRsJaAA==",
      "type": "package",
      "path": "microsoft.bcl.timeprovider/8.0.1",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Bcl.TimeProvider.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Bcl.TimeProvider.targets",
        "lib/net462/Microsoft.Bcl.TimeProvider.dll",
        "lib/net462/Microsoft.Bcl.TimeProvider.xml",
        "lib/net8.0/Microsoft.Bcl.TimeProvider.dll",
        "lib/net8.0/Microsoft.Bcl.TimeProvider.xml",
        "lib/netstandard2.0/Microsoft.Bcl.TimeProvider.dll",
        "lib/netstandard2.0/Microsoft.Bcl.TimeProvider.xml",
        "microsoft.bcl.timeprovider.8.0.1.nupkg.sha512",
        "microsoft.bcl.timeprovider.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Data.Sqlite.Core/8.0.10": {
      "sha512": "i95bgLqp6rJzmhQEtGhVVHnk1nYAhr/pLDul676PnwI/d7uDSSGs2ZPU9aP0VOuppkZaNinQOUCrD7cstDbQiQ==",
      "type": "package",
      "path": "microsoft.data.sqlite.core/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "PACKAGE.md",
        "lib/net6.0/Microsoft.Data.Sqlite.dll",
        "lib/net6.0/Microsoft.Data.Sqlite.xml",
        "lib/net8.0/Microsoft.Data.Sqlite.dll",
        "lib/net8.0/Microsoft.Data.Sqlite.xml",
        "lib/netstandard2.0/Microsoft.Data.Sqlite.dll",
        "lib/netstandard2.0/Microsoft.Data.Sqlite.xml",
        "microsoft.data.sqlite.core.8.0.10.nupkg.sha512",
        "microsoft.data.sqlite.core.nuspec"
      ]
    },
    "Microsoft.EntityFrameworkCore/8.0.10": {
      "sha512": "PPkQdIqfR1nU3n6YgGGDk8G+eaYbaAKM1AzIQtlPNTKf10Osg3N9T+iK9AlnSA/ujsK00flPpFHVfJrbuBFS1A==",
      "type": "package",
      "path": "microsoft.entityframeworkcore/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "PACKAGE.md",
        "buildTransitive/net8.0/Microsoft.EntityFrameworkCore.props",
        "lib/net8.0/Microsoft.EntityFrameworkCore.dll",
        "lib/net8.0/Microsoft.EntityFrameworkCore.xml",
        "microsoft.entityframeworkcore.8.0.10.nupkg.sha512",
        "microsoft.entityframeworkcore.nuspec"
      ]
    },
    "Microsoft.EntityFrameworkCore.Abstractions/8.0.10": {
      "sha512": "FV0QlcX9INY4kAD2o72uPtyOh0nZut2jB11Jf9mNYBtHay8gDLe+x4AbXFwuQg+eSvofjT7naV82e827zGfyMg==",
      "type": "package",
      "path": "microsoft.entityframeworkcore.abstractions/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "PACKAGE.md",
        "lib/net8.0/Microsoft.EntityFrameworkCore.Abstractions.dll",
        "lib/net8.0/Microsoft.EntityFrameworkCore.Abstractions.xml",
        "microsoft.entityframeworkcore.abstractions.8.0.10.nupkg.sha512",
        "microsoft.entityframeworkcore.abstractions.nuspec"
      ]
    },
    "Microsoft.EntityFrameworkCore.Analyzers/8.0.10": {
      "sha512": "51KkPIc0EMv/gVXhPIUi6cwJE9Mvh+PLr4Lap4naLcsoGZ0lF2SvOPgUUprwRV3MnN7nyD1XPhT5RJ/p+xFAXw==",
      "type": "package",
      "path": "microsoft.entityframeworkcore.analyzers/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "analyzers/dotnet/cs/Microsoft.EntityFrameworkCore.Analyzers.dll",
        "docs/PACKAGE.md",
        "lib/netstandard2.0/_._",
        "microsoft.entityframeworkcore.analyzers.8.0.10.nupkg.sha512",
        "microsoft.entityframeworkcore.analyzers.nuspec"
      ]
    },
    "Microsoft.EntityFrameworkCore.Relational/8.0.10": {
      "sha512": "OefBEE47kGKPRPV3OT+FAW6o5BFgLk2D9EoeWVy7NbOepzUneayLQxbVE098FfedTyMwxvZQoDD9LrvZc3MadA==",
      "type": "package",
      "path": "microsoft.entityframeworkcore.relational/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "PACKAGE.md",
        "lib/net8.0/Microsoft.EntityFrameworkCore.Relational.dll",
        "lib/net8.0/Microsoft.EntityFrameworkCore.Relational.xml",
        "microsoft.entityframeworkcore.relational.8.0.10.nupkg.sha512",
        "microsoft.entityframeworkcore.relational.nuspec"
      ]
    },
    "Microsoft.EntityFrameworkCore.Sqlite/8.0.10": {
      "sha512": "inVXiKuOczjNVpLKG0nsnUmgL2m/bo6H/p4DCFVGRImJj6p9qrlwnU96A5FNZ56BF9VE1uZOULqgGTGTFVS19A==",
      "type": "package",
      "path": "microsoft.entityframeworkcore.sqlite/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "PACKAGE.md",
        "lib/net8.0/_._",
        "microsoft.entityframeworkcore.sqlite.8.0.10.nupkg.sha512",
        "microsoft.entityframeworkcore.sqlite.nuspec"
      ]
    },
    "Microsoft.EntityFrameworkCore.Sqlite.Core/8.0.10": {
      "sha512": "dmpgFx5BPqw/jJmBh9gp0UJpCcNDvWnGMoc9XHwp4K0h9skBE6A8E7+AwSiz556iyVf8Gn/qxHF1cgX9ZqGiYQ==",
      "type": "package",
      "path": "microsoft.entityframeworkcore.sqlite.core/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "PACKAGE.md",
        "lib/net8.0/Microsoft.EntityFrameworkCore.Sqlite.dll",
        "lib/net8.0/Microsoft.EntityFrameworkCore.Sqlite.xml",
        "microsoft.entityframeworkcore.sqlite.core.8.0.10.nupkg.sha512",
        "microsoft.entityframeworkcore.sqlite.core.nuspec"
      ]
    },
    "Microsoft.Extensions.ApiDescription.Server/6.0.5": {
      "sha512": "Ckb5EDBUNJdFWyajfXzUIMRkhf52fHZOQuuZg/oiu8y7zDCVwD0iHhew6MnThjHmevanpxL3f5ci2TtHQEN6bw==",
      "type": "package",
      "path": "microsoft.extensions.apidescription.server/6.0.5",
      "hasTools": true,
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "build/Microsoft.Extensions.ApiDescription.Server.props",
        "build/Microsoft.Extensions.ApiDescription.Server.targets",
        "buildMultiTargeting/Microsoft.Extensions.ApiDescription.Server.props",
        "buildMultiTargeting/Microsoft.Extensions.ApiDescription.Server.targets",
        "microsoft.extensions.apidescription.server.6.0.5.nupkg.sha512",
        "microsoft.extensions.apidescription.server.nuspec",
        "tools/Newtonsoft.Json.dll",
        "tools/dotnet-getdocument.deps.json",
        "tools/dotnet-getdocument.dll",
        "tools/dotnet-getdocument.runtimeconfig.json",
        "tools/net461-x86/GetDocument.Insider.exe",
        "tools/net461-x86/GetDocument.Insider.exe.config",
        "tools/net461-x86/Microsoft.Win32.Primitives.dll",
        "tools/net461-x86/System.AppContext.dll",
        "tools/net461-x86/System.Buffers.dll",
        "tools/net461-x86/System.Collections.Concurrent.dll",
        "tools/net461-x86/System.Collections.NonGeneric.dll",
        "tools/net461-x86/System.Collections.Specialized.dll",
        "tools/net461-x86/System.Collections.dll",
        "tools/net461-x86/System.ComponentModel.EventBasedAsync.dll",
        "tools/net461-x86/System.ComponentModel.Primitives.dll",
        "tools/net461-x86/System.ComponentModel.TypeConverter.dll",
        "tools/net461-x86/System.ComponentModel.dll",
        "tools/net461-x86/System.Console.dll",
        "tools/net461-x86/System.Data.Common.dll",
        "tools/net461-x86/System.Diagnostics.Contracts.dll",
        "tools/net461-x86/System.Diagnostics.Debug.dll",
        "tools/net461-x86/System.Diagnostics.DiagnosticSource.dll",
        "tools/net461-x86/System.Diagnostics.FileVersionInfo.dll",
        "tools/net461-x86/System.Diagnostics.Process.dll",
        "tools/net461-x86/System.Diagnostics.StackTrace.dll",
        "tools/net461-x86/System.Diagnostics.TextWriterTraceListener.dll",
        "tools/net461-x86/System.Diagnostics.Tools.dll",
        "tools/net461-x86/System.Diagnostics.TraceSource.dll",
        "tools/net461-x86/System.Diagnostics.Tracing.dll",
        "tools/net461-x86/System.Drawing.Primitives.dll",
        "tools/net461-x86/System.Dynamic.Runtime.dll",
        "tools/net461-x86/System.Globalization.Calendars.dll",
        "tools/net461-x86/System.Globalization.Extensions.dll",
        "tools/net461-x86/System.Globalization.dll",
        "tools/net461-x86/System.IO.Compression.ZipFile.dll",
        "tools/net461-x86/System.IO.Compression.dll",
        "tools/net461-x86/System.IO.FileSystem.DriveInfo.dll",
        "tools/net461-x86/System.IO.FileSystem.Primitives.dll",
        "tools/net461-x86/System.IO.FileSystem.Watcher.dll",
        "tools/net461-x86/System.IO.FileSystem.dll",
        "tools/net461-x86/System.IO.IsolatedStorage.dll",
        "tools/net461-x86/System.IO.MemoryMappedFiles.dll",
        "tools/net461-x86/System.IO.Pipes.dll",
        "tools/net461-x86/System.IO.UnmanagedMemoryStream.dll",
        "tools/net461-x86/System.IO.dll",
        "tools/net461-x86/System.Linq.Expressions.dll",
        "tools/net461-x86/System.Linq.Parallel.dll",
        "tools/net461-x86/System.Linq.Queryable.dll",
        "tools/net461-x86/System.Linq.dll",
        "tools/net461-x86/System.Memory.dll",
        "tools/net461-x86/System.Net.Http.dll",
        "tools/net461-x86/System.Net.NameResolution.dll",
        "tools/net461-x86/System.Net.NetworkInformation.dll",
        "tools/net461-x86/System.Net.Ping.dll",
        "tools/net461-x86/System.Net.Primitives.dll",
        "tools/net461-x86/System.Net.Requests.dll",
        "tools/net461-x86/System.Net.Security.dll",
        "tools/net461-x86/System.Net.Sockets.dll",
        "tools/net461-x86/System.Net.WebHeaderCollection.dll",
        "tools/net461-x86/System.Net.WebSockets.Client.dll",
        "tools/net461-x86/System.Net.WebSockets.dll",
        "tools/net461-x86/System.Numerics.Vectors.dll",
        "tools/net461-x86/System.ObjectModel.dll",
        "tools/net461-x86/System.Reflection.Extensions.dll",
        "tools/net461-x86/System.Reflection.Primitives.dll",
        "tools/net461-x86/System.Reflection.dll",
        "tools/net461-x86/System.Resources.Reader.dll",
        "tools/net461-x86/System.Resources.ResourceManager.dll",
        "tools/net461-x86/System.Resources.Writer.dll",
        "tools/net461-x86/System.Runtime.CompilerServices.Unsafe.dll",
        "tools/net461-x86/System.Runtime.CompilerServices.VisualC.dll",
        "tools/net461-x86/System.Runtime.Extensions.dll",
        "tools/net461-x86/System.Runtime.Handles.dll",
        "tools/net461-x86/System.Runtime.InteropServices.RuntimeInformation.dll",
        "tools/net461-x86/System.Runtime.InteropServices.dll",
        "tools/net461-x86/System.Runtime.Numerics.dll",
        "tools/net461-x86/System.Runtime.Serialization.Formatters.dll",
        "tools/net461-x86/System.Runtime.Serialization.Json.dll",
        "tools/net461-x86/System.Runtime.Serialization.Primitives.dll",
        "tools/net461-x86/System.Runtime.Serialization.Xml.dll",
        "tools/net461-x86/System.Runtime.dll",
        "tools/net461-x86/System.Security.Claims.dll",
        "tools/net461-x86/System.Security.Cryptography.Algorithms.dll",
        "tools/net461-x86/System.Security.Cryptography.Csp.dll",
        "tools/net461-x86/System.Security.Cryptography.Encoding.dll",
        "tools/net461-x86/System.Security.Cryptography.Primitives.dll",
        "tools/net461-x86/System.Security.Cryptography.X509Certificates.dll",
        "tools/net461-x86/System.Security.Principal.dll",
        "tools/net461-x86/System.Security.SecureString.dll",
        "tools/net461-x86/System.Text.Encoding.Extensions.dll",
        "tools/net461-x86/System.Text.Encoding.dll",
        "tools/net461-x86/System.Text.RegularExpressions.dll",
        "tools/net461-x86/System.Threading.Overlapped.dll",
        "tools/net461-x86/System.Threading.Tasks.Parallel.dll",
        "tools/net461-x86/System.Threading.Tasks.dll",
        "tools/net461-x86/System.Threading.Thread.dll",
        "tools/net461-x86/System.Threading.ThreadPool.dll",
        "tools/net461-x86/System.Threading.Timer.dll",
        "tools/net461-x86/System.Threading.dll",
        "tools/net461-x86/System.ValueTuple.dll",
        "tools/net461-x86/System.Xml.ReaderWriter.dll",
        "tools/net461-x86/System.Xml.XDocument.dll",
        "tools/net461-x86/System.Xml.XPath.XDocument.dll",
        "tools/net461-x86/System.Xml.XPath.dll",
        "tools/net461-x86/System.Xml.XmlDocument.dll",
        "tools/net461-x86/System.Xml.XmlSerializer.dll",
        "tools/net461-x86/netstandard.dll",
        "tools/net461/GetDocument.Insider.exe",
        "tools/net461/GetDocument.Insider.exe.config",
        "tools/net461/Microsoft.Win32.Primitives.dll",
        "tools/net461/System.AppContext.dll",
        "tools/net461/System.Buffers.dll",
        "tools/net461/System.Collections.Concurrent.dll",
        "tools/net461/System.Collections.NonGeneric.dll",
        "tools/net461/System.Collections.Specialized.dll",
        "tools/net461/System.Collections.dll",
        "tools/net461/System.ComponentModel.EventBasedAsync.dll",
        "tools/net461/System.ComponentModel.Primitives.dll",
        "tools/net461/System.ComponentModel.TypeConverter.dll",
        "tools/net461/System.ComponentModel.dll",
        "tools/net461/System.Console.dll",
        "tools/net461/System.Data.Common.dll",
        "tools/net461/System.Diagnostics.Contracts.dll",
        "tools/net461/System.Diagnostics.Debug.dll",
        "tools/net461/System.Diagnostics.DiagnosticSource.dll",
        "tools/net461/System.Diagnostics.FileVersionInfo.dll",
        "tools/net461/System.Diagnostics.Process.dll",
        "tools/net461/System.Diagnostics.StackTrace.dll",
        "tools/net461/System.Diagnostics.TextWriterTraceListener.dll",
        "tools/net461/System.Diagnostics.Tools.dll",
        "tools/net461/System.Diagnostics.TraceSource.dll",
        "tools/net461/System.Diagnostics.Tracing.dll",
        "tools/net461/System.Drawing.Primitives.dll",
        "tools/net461/System.Dynamic.Runtime.dll",
        "tools/net461/System.Globalization.Calendars.dll",
        "tools/net461/System.Globalization.Extensions.dll",
        "tools/net461/System.Globalization.dll",
        "tools/net461/System.IO.Compression.ZipFile.dll",
        "tools/net461/System.IO.Compression.dll",
        "tools/net461/System.IO.FileSystem.DriveInfo.dll",
        "tools/net461/System.IO.FileSystem.Primitives.dll",
        "tools/net461/System.IO.FileSystem.Watcher.dll",
        "tools/net461/System.IO.FileSystem.dll",
        "tools/net461/System.IO.IsolatedStorage.dll",
        "tools/net461/System.IO.MemoryMappedFiles.dll",
        "tools/net461/System.IO.Pipes.dll",
        "tools/net461/System.IO.UnmanagedMemoryStream.dll",
        "tools/net461/System.IO.dll",
        "tools/net461/System.Linq.Expressions.dll",
        "tools/net461/System.Linq.Parallel.dll",
        "tools/net461/System.Linq.Queryable.dll",
        "tools/net461/System.Linq.dll",
        "tools/net461/System.Memory.dll",
        "tools/net461/System.Net.Http.dll",
        "tools/net461/System.Net.NameResolution.dll",
        "tools/net461/System.Net.NetworkInformation.dll",
        "tools/net461/System.Net.Ping.dll",
        "tools/net461/System.Net.Primitives.dll",
        "tools/net461/System.Net.Requests.dll",
        "tools/net461/System.Net.Security.dll",
        "tools/net461/System.Net.Sockets.dll",
        "tools/net461/System.Net.WebHeaderCollection.dll",
        "tools/net461/System.Net.WebSockets.Client.dll",
        "tools/net461/System.Net.WebSockets.dll",
        "tools/net461/System.Numerics.Vectors.dll",
        "tools/net461/System.ObjectModel.dll",
        "tools/net461/System.Reflection.Extensions.dll",
        "tools/net461/System.Reflection.Primitives.dll",
        "tools/net461/System.Reflection.dll",
        "tools/net461/System.Resources.Reader.dll",
        "tools/net461/System.Resources.ResourceManager.dll",
        "tools/net461/System.Resources.Writer.dll",
        "tools/net461/System.Runtime.CompilerServices.Unsafe.dll",
        "tools/net461/System.Runtime.CompilerServices.VisualC.dll",
        "tools/net461/System.Runtime.Extensions.dll",
        "tools/net461/System.Runtime.Handles.dll",
        "tools/net461/System.Runtime.InteropServices.RuntimeInformation.dll",
        "tools/net461/System.Runtime.InteropServices.dll",
        "tools/net461/System.Runtime.Numerics.dll",
        "tools/net461/System.Runtime.Serialization.Formatters.dll",
        "tools/net461/System.Runtime.Serialization.Json.dll",
        "tools/net461/System.Runtime.Serialization.Primitives.dll",
        "tools/net461/System.Runtime.Serialization.Xml.dll",
        "tools/net461/System.Runtime.dll",
        "tools/net461/System.Security.Claims.dll",
        "tools/net461/System.Security.Cryptography.Algorithms.dll",
        "tools/net461/System.Security.Cryptography.Csp.dll",
        "tools/net461/System.Security.Cryptography.Encoding.dll",
        "tools/net461/System.Security.Cryptography.Primitives.dll",
        "tools/net461/System.Security.Cryptography.X509Certificates.dll",
        "tools/net461/System.Security.Principal.dll",
        "tools/net461/System.Security.SecureString.dll",
        "tools/net461/System.Text.Encoding.Extensions.dll",
        "tools/net461/System.Text.Encoding.dll",
        "tools/net461/System.Text.RegularExpressions.dll",
        "tools/net461/System.Threading.Overlapped.dll",
        "tools/net461/System.Threading.Tasks.Parallel.dll",
        "tools/net461/System.Threading.Tasks.dll",
        "tools/net461/System.Threading.Thread.dll",
        "tools/net461/System.Threading.ThreadPool.dll",
        "tools/net461/System.Threading.Timer.dll",
        "tools/net461/System.Threading.dll",
        "tools/net461/System.ValueTuple.dll",
        "tools/net461/System.Xml.ReaderWriter.dll",
        "tools/net461/System.Xml.XDocument.dll",
        "tools/net461/System.Xml.XPath.XDocument.dll",
        "tools/net461/System.Xml.XPath.dll",
        "tools/net461/System.Xml.XmlDocument.dll",
        "tools/net461/System.Xml.XmlSerializer.dll",
        "tools/net461/netstandard.dll",
        "tools/netcoreapp2.1/GetDocument.Insider.deps.json",
        "tools/netcoreapp2.1/GetDocument.Insider.dll",
        "tools/netcoreapp2.1/GetDocument.Insider.runtimeconfig.json",
        "tools/netcoreapp2.1/System.Diagnostics.DiagnosticSource.dll"
      ]
    },
    "Microsoft.Extensions.Caching.Abstractions/8.0.0": {
      "sha512": "3KuSxeHoNYdxVYfg2IRZCThcrlJ1XJqIXkAWikCsbm5C/bCjv7G0WoKDyuR98Q+T607QT2Zl5GsbGRkENcV2yQ==",
      "type": "package",
      "path": "microsoft.extensions.caching.abstractions/8.0.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.Caching.Abstractions.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.Caching.Abstractions.targets",
        "lib/net462/Microsoft.Extensions.Caching.Abstractions.dll",
        "lib/net462/Microsoft.Extensions.Caching.Abstractions.xml",
        "lib/net6.0/Microsoft.Extensions.Caching.Abstractions.dll",
        "lib/net6.0/Microsoft.Extensions.Caching.Abstractions.xml",
        "lib/net7.0/Microsoft.Extensions.Caching.Abstractions.dll",
        "lib/net7.0/Microsoft.Extensions.Caching.Abstractions.xml",
        "lib/net8.0/Microsoft.Extensions.Caching.Abstractions.dll",
        "lib/net8.0/Microsoft.Extensions.Caching.Abstractions.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Caching.Abstractions.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Caching.Abstractions.xml",
        "microsoft.extensions.caching.abstractions.8.0.0.nupkg.sha512",
        "microsoft.extensions.caching.abstractions.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.Caching.Memory/8.0.1": {
      "sha512": "HFDnhYLccngrzyGgHkjEDU5FMLn4MpOsr5ElgsBMC4yx6lJh4jeWO7fHS8+TXPq+dgxCmUa/Trl8svObmwW4QA==",
      "type": "package",
      "path": "microsoft.extensions.caching.memory/8.0.1",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.Caching.Memory.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.Caching.Memory.targets",
        "lib/net462/Microsoft.Extensions.Caching.Memory.dll",
        "lib/net462/Microsoft.Extensions.Caching.Memory.xml",
        "lib/net6.0/Microsoft.Extensions.Caching.Memory.dll",
        "lib/net6.0/Microsoft.Extensions.Caching.Memory.xml",
        "lib/net7.0/Microsoft.Extensions.Caching.Memory.dll",
        "lib/net7.0/Microsoft.Extensions.Caching.Memory.xml",
        "lib/net8.0/Microsoft.Extensions.Caching.Memory.dll",
        "lib/net8.0/Microsoft.Extensions.Caching.Memory.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Caching.Memory.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Caching.Memory.xml",
        "microsoft.extensions.caching.memory.8.0.1.nupkg.sha512",
        "microsoft.extensions.caching.memory.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.Configuration.Abstractions/8.0.0": {
      "sha512": "3lE/iLSutpgX1CC0NOW70FJoGARRHbyKmG7dc0klnUZ9Dd9hS6N/POPWhKhMLCEuNN5nXEY5agmlFtH562vqhQ==",
      "type": "package",
      "path": "microsoft.extensions.configuration.abstractions/8.0.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.Configuration.Abstractions.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.Configuration.Abstractions.targets",
        "lib/net462/Microsoft.Extensions.Configuration.Abstractions.dll",
        "lib/net462/Microsoft.Extensions.Configuration.Abstractions.xml",
        "lib/net6.0/Microsoft.Extensions.Configuration.Abstractions.dll",
        "lib/net6.0/Microsoft.Extensions.Configuration.Abstractions.xml",
        "lib/net7.0/Microsoft.Extensions.Configuration.Abstractions.dll",
        "lib/net7.0/Microsoft.Extensions.Configuration.Abstractions.xml",
        "lib/net8.0/Microsoft.Extensions.Configuration.Abstractions.dll",
        "lib/net8.0/Microsoft.Extensions.Configuration.Abstractions.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Configuration.Abstractions.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Configuration.Abstractions.xml",
        "microsoft.extensions.configuration.abstractions.8.0.0.nupkg.sha512",
        "microsoft.extensions.configuration.abstractions.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.DependencyInjection/8.0.1": {
      "sha512": "BmANAnR5Xd4Oqw7yQ75xOAYODybZQRzdeNucg7kS5wWKd2PNnMdYtJ2Vciy0QLylRmv42DGl5+AFL9izA6F1Rw==",
      "type": "package",
      "path": "microsoft.extensions.dependencyinjection/8.0.1",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.DependencyInjection.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.DependencyInjection.targets",
        "lib/net462/Microsoft.Extensions.DependencyInjection.dll",
        "lib/net462/Microsoft.Extensions.DependencyInjection.xml",
        "lib/net6.0/Microsoft.Extensions.DependencyInjection.dll",
        "lib/net6.0/Microsoft.Extensions.DependencyInjection.xml",
        "lib/net7.0/Microsoft.Extensions.DependencyInjection.dll",
        "lib/net7.0/Microsoft.Extensions.DependencyInjection.xml",
        "lib/net8.0/Microsoft.Extensions.DependencyInjection.dll",
        "lib/net8.0/Microsoft.Extensions.DependencyInjection.xml",
        "lib/netstandard2.0/Microsoft.Extensions.DependencyInjection.dll",
        "lib/netstandard2.0/Microsoft.Extensions.DependencyInjection.xml",
        "lib/netstandard2.1/Microsoft.Extensions.DependencyInjection.dll",
        "lib/netstandard2.1/Microsoft.Extensions.DependencyInjection.xml",
        "microsoft.extensions.dependencyinjection.8.0.1.nupkg.sha512",
        "microsoft.extensions.dependencyinjection.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.DependencyInjection.Abstractions/8.0.2": {
      "sha512": "3iE7UF7MQkCv1cxzCahz+Y/guQbTqieyxyaWKhrRO91itI9cOKO76OHeQDahqG4MmW5umr3CcCvGmK92lWNlbg==",
      "type": "package",
      "path": "microsoft.extensions.dependencyinjection.abstractions/8.0.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.DependencyInjection.Abstractions.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.DependencyInjection.Abstractions.targets",
        "lib/net462/Microsoft.Extensions.DependencyInjection.Abstractions.dll",
        "lib/net462/Microsoft.Extensions.DependencyInjection.Abstractions.xml",
        "lib/net6.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll",
        "lib/net6.0/Microsoft.Extensions.DependencyInjection.Abstractions.xml",
        "lib/net7.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll",
        "lib/net7.0/Microsoft.Extensions.DependencyInjection.Abstractions.xml",
        "lib/net8.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll",
        "lib/net8.0/Microsoft.Extensions.DependencyInjection.Abstractions.xml",
        "lib/netstandard2.0/Microsoft.Extensions.DependencyInjection.Abstractions.dll",
        "lib/netstandard2.0/Microsoft.Extensions.DependencyInjection.Abstractions.xml",
        "lib/netstandard2.1/Microsoft.Extensions.DependencyInjection.Abstractions.dll",
        "lib/netstandard2.1/Microsoft.Extensions.DependencyInjection.Abstractions.xml",
        "microsoft.extensions.dependencyinjection.abstractions.8.0.2.nupkg.sha512",
        "microsoft.extensions.dependencyinjection.abstractions.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.DependencyModel/8.0.2": {
      "sha512": "mUBDZZRgZrSyFOsJ2qJJ9fXfqd/kXJwf3AiDoqLD9m6TjY5OO/vLNOb9fb4juC0487eq4hcGN/M2Rh/CKS7QYw==",
      "type": "package",
      "path": "microsoft.extensions.dependencymodel/8.0.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.DependencyModel.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.DependencyModel.targets",
        "lib/net462/Microsoft.Extensions.DependencyModel.dll",
        "lib/net462/Microsoft.Extensions.DependencyModel.xml",
        "lib/net6.0/Microsoft.Extensions.DependencyModel.dll",
        "lib/net6.0/Microsoft.Extensions.DependencyModel.xml",
        "lib/net7.0/Microsoft.Extensions.DependencyModel.dll",
        "lib/net7.0/Microsoft.Extensions.DependencyModel.xml",
        "lib/net8.0/Microsoft.Extensions.DependencyModel.dll",
        "lib/net8.0/Microsoft.Extensions.DependencyModel.xml",
        "lib/netstandard2.0/Microsoft.Extensions.DependencyModel.dll",
        "lib/netstandard2.0/Microsoft.Extensions.DependencyModel.xml",
        "microsoft.extensions.dependencymodel.8.0.2.nupkg.sha512",
        "microsoft.extensions.dependencymodel.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.Identity.Core/8.0.10": {
      "sha512": "tS0lNRccAxuAeIVxLBDdklSOL2vAzVUcYqY0njsRbJpNYrXNIKVeQGmhPJgBU0Vrq+iu0LLJ4KLCqGxsOIWpyw==",
      "type": "package",
      "path": "microsoft.extensions.identity.core/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/net462/Microsoft.Extensions.Identity.Core.dll",
        "lib/net462/Microsoft.Extensions.Identity.Core.xml",
        "lib/net8.0/Microsoft.Extensions.Identity.Core.dll",
        "lib/net8.0/Microsoft.Extensions.Identity.Core.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Identity.Core.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Identity.Core.xml",
        "microsoft.extensions.identity.core.8.0.10.nupkg.sha512",
        "microsoft.extensions.identity.core.nuspec"
      ]
    },
    "Microsoft.Extensions.Identity.Stores/8.0.10": {
      "sha512": "Mwxhj2pLwFcT8BOJ4g7y/WQyQSmZNOalIHmyISFlWykPEKgaQXOlddOCOftSIUqh4IZEYDsVXjeecjl9RLC8Lw==",
      "type": "package",
      "path": "microsoft.extensions.identity.stores/8.0.10",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/net462/Microsoft.Extensions.Identity.Stores.dll",
        "lib/net462/Microsoft.Extensions.Identity.Stores.xml",
        "lib/net8.0/Microsoft.Extensions.Identity.Stores.dll",
        "lib/net8.0/Microsoft.Extensions.Identity.Stores.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Identity.Stores.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Identity.Stores.xml",
        "microsoft.extensions.identity.stores.8.0.10.nupkg.sha512",
        "microsoft.extensions.identity.stores.nuspec"
      ]
    },
    "Microsoft.Extensions.Logging/8.0.1": {
      "sha512": "4x+pzsQEbqxhNf1QYRr5TDkLP9UsLT3A6MdRKDDEgrW7h1ljiEPgTNhKYUhNCCAaVpQECVQ+onA91PTPnIp6Lw==",
      "type": "package",
      "path": "microsoft.extensions.logging/8.0.1",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.Logging.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.Logging.targets",
        "lib/net462/Microsoft.Extensions.Logging.dll",
        "lib/net462/Microsoft.Extensions.Logging.xml",
        "lib/net6.0/Microsoft.Extensions.Logging.dll",
        "lib/net6.0/Microsoft.Extensions.Logging.xml",
        "lib/net7.0/Microsoft.Extensions.Logging.dll",
        "lib/net7.0/Microsoft.Extensions.Logging.xml",
        "lib/net8.0/Microsoft.Extensions.Logging.dll",
        "lib/net8.0/Microsoft.Extensions.Logging.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Logging.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Logging.xml",
        "lib/netstandard2.1/Microsoft.Extensions.Logging.dll",
        "lib/netstandard2.1/Microsoft.Extensions.Logging.xml",
        "microsoft.extensions.logging.8.0.1.nupkg.sha512",
        "microsoft.extensions.logging.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.Logging.Abstractions/8.0.2": {
      "sha512": "nroMDjS7hNBPtkZqVBbSiQaQjWRDxITI8Y7XnDs97rqG3EbzVTNLZQf7bIeUJcaHOV8bca47s1Uxq94+2oGdxA==",
      "type": "package",
      "path": "microsoft.extensions.logging.abstractions/8.0.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "analyzers/dotnet/roslyn3.11/cs/Microsoft.Extensions.Logging.Generators.dll",
        "analyzers/dotnet/roslyn3.11/cs/cs/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/de/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/es/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/fr/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/it/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/ja/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/ko/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/pl/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/pt-BR/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/ru/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/tr/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/zh-Hans/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn3.11/cs/zh-Hant/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/Microsoft.Extensions.Logging.Generators.dll",
        "analyzers/dotnet/roslyn4.0/cs/cs/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/de/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/es/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/fr/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/it/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/ja/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/ko/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/pl/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/pt-BR/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/ru/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/tr/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/zh-Hans/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.0/cs/zh-Hant/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/Microsoft.Extensions.Logging.Generators.dll",
        "analyzers/dotnet/roslyn4.4/cs/cs/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/de/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/es/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/fr/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/it/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/ja/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/ko/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/pl/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/pt-BR/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/ru/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/tr/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/zh-Hans/Microsoft.Extensions.Logging.Generators.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/zh-Hant/Microsoft.Extensions.Logging.Generators.resources.dll",
        "buildTransitive/net461/Microsoft.Extensions.Logging.Abstractions.targets",
        "buildTransitive/net462/Microsoft.Extensions.Logging.Abstractions.targets",
        "buildTransitive/net6.0/Microsoft.Extensions.Logging.Abstractions.targets",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.Logging.Abstractions.targets",
        "buildTransitive/netstandard2.0/Microsoft.Extensions.Logging.Abstractions.targets",
        "lib/net462/Microsoft.Extensions.Logging.Abstractions.dll",
        "lib/net462/Microsoft.Extensions.Logging.Abstractions.xml",
        "lib/net6.0/Microsoft.Extensions.Logging.Abstractions.dll",
        "lib/net6.0/Microsoft.Extensions.Logging.Abstractions.xml",
        "lib/net7.0/Microsoft.Extensions.Logging.Abstractions.dll",
        "lib/net7.0/Microsoft.Extensions.Logging.Abstractions.xml",
        "lib/net8.0/Microsoft.Extensions.Logging.Abstractions.dll",
        "lib/net8.0/Microsoft.Extensions.Logging.Abstractions.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Logging.Abstractions.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Logging.Abstractions.xml",
        "microsoft.extensions.logging.abstractions.8.0.2.nupkg.sha512",
        "microsoft.extensions.logging.abstractions.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.Options/8.0.2": {
      "sha512": "dWGKvhFybsaZpGmzkGCbNNwBD1rVlWzrZKANLW/CcbFJpCEceMCGzT7zZwHOGBCbwM0SzBuceMj5HN1LKV1QqA==",
      "type": "package",
      "path": "microsoft.extensions.options/8.0.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "analyzers/dotnet/roslyn4.4/cs/Microsoft.Extensions.Options.SourceGeneration.dll",
        "analyzers/dotnet/roslyn4.4/cs/cs/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/de/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/es/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/fr/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/it/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/ja/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/ko/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/pl/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/pt-BR/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/ru/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/tr/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/zh-Hans/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "analyzers/dotnet/roslyn4.4/cs/zh-Hant/Microsoft.Extensions.Options.SourceGeneration.resources.dll",
        "buildTransitive/net461/Microsoft.Extensions.Options.targets",
        "buildTransitive/net462/Microsoft.Extensions.Options.targets",
        "buildTransitive/net6.0/Microsoft.Extensions.Options.targets",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.Options.targets",
        "buildTransitive/netstandard2.0/Microsoft.Extensions.Options.targets",
        "lib/net462/Microsoft.Extensions.Options.dll",
        "lib/net462/Microsoft.Extensions.Options.xml",
        "lib/net6.0/Microsoft.Extensions.Options.dll",
        "lib/net6.0/Microsoft.Extensions.Options.xml",
        "lib/net7.0/Microsoft.Extensions.Options.dll",
        "lib/net7.0/Microsoft.Extensions.Options.xml",
        "lib/net8.0/Microsoft.Extensions.Options.dll",
        "lib/net8.0/Microsoft.Extensions.Options.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Options.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Options.xml",
        "lib/netstandard2.1/Microsoft.Extensions.Options.dll",
        "lib/netstandard2.1/Microsoft.Extensions.Options.xml",
        "microsoft.extensions.options.8.0.2.nupkg.sha512",
        "microsoft.extensions.options.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.Extensions.Primitives/8.0.0": {
      "sha512": "bXJEZrW9ny8vjMF1JV253WeLhpEVzFo1lyaZu1vQ4ZxWUlVvknZ/+ftFgVheLubb4eZPSwwxBeqS1JkCOjxd8g==",
      "type": "package",
      "path": "microsoft.extensions.primitives/8.0.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/Microsoft.Extensions.Primitives.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/Microsoft.Extensions.Primitives.targets",
        "lib/net462/Microsoft.Extensions.Primitives.dll",
        "lib/net462/Microsoft.Extensions.Primitives.xml",
        "lib/net6.0/Microsoft.Extensions.Primitives.dll",
        "lib/net6.0/Microsoft.Extensions.Primitives.xml",
        "lib/net7.0/Microsoft.Extensions.Primitives.dll",
        "lib/net7.0/Microsoft.Extensions.Primitives.xml",
        "lib/net8.0/Microsoft.Extensions.Primitives.dll",
        "lib/net8.0/Microsoft.Extensions.Primitives.xml",
        "lib/netstandard2.0/Microsoft.Extensions.Primitives.dll",
        "lib/netstandard2.0/Microsoft.Extensions.Primitives.xml",
        "microsoft.extensions.primitives.8.0.0.nupkg.sha512",
        "microsoft.extensions.primitives.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Microsoft.IdentityModel.Abstractions/8.1.2": {
      "sha512": "QSSDer3kvyTdNq6BefgX4EYi1lsia2zJUh5CfIMZFQUh6BhrXK1WE4i2C9ltUmmuUjoeVVX6AaSo9NZfpTGNdw==",
      "type": "package",
      "path": "microsoft.identitymodel.abstractions/8.1.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "lib/net462/Microsoft.IdentityModel.Abstractions.dll",
        "lib/net462/Microsoft.IdentityModel.Abstractions.xml",
        "lib/net472/Microsoft.IdentityModel.Abstractions.dll",
        "lib/net472/Microsoft.IdentityModel.Abstractions.xml",
        "lib/net6.0/Microsoft.IdentityModel.Abstractions.dll",
        "lib/net6.0/Microsoft.IdentityModel.Abstractions.xml",
        "lib/net8.0/Microsoft.IdentityModel.Abstractions.dll",
        "lib/net8.0/Microsoft.IdentityModel.Abstractions.xml",
        "lib/net9.0/Microsoft.IdentityModel.Abstractions.dll",
        "lib/net9.0/Microsoft.IdentityModel.Abstractions.xml",
        "lib/netstandard2.0/Microsoft.IdentityModel.Abstractions.dll",
        "lib/netstandard2.0/Microsoft.IdentityModel.Abstractions.xml",
        "microsoft.identitymodel.abstractions.8.1.2.nupkg.sha512",
        "microsoft.identitymodel.abstractions.nuspec"
      ]
    },
    "Microsoft.IdentityModel.JsonWebTokens/8.1.2": {
      "sha512": "AWQINMvtamdYBqtG8q8muyYTfA9i5xRBEsMKQdzOn5xRzhVVDSzsNGYof1docfF3pX4hNRUpHlzs61RP0reZMw==",
      "type": "package",
      "path": "microsoft.identitymodel.jsonwebtokens/8.1.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "lib/net462/Microsoft.IdentityModel.JsonWebTokens.dll",
        "lib/net462/Microsoft.IdentityModel.JsonWebTokens.xml",
        "lib/net472/Microsoft.IdentityModel.JsonWebTokens.dll",
        "lib/net472/Microsoft.IdentityModel.JsonWebTokens.xml",
        "lib/net6.0/Microsoft.IdentityModel.JsonWebTokens.dll",
        "lib/net6.0/Microsoft.IdentityModel.JsonWebTokens.xml",
        "lib/net8.0/Microsoft.IdentityModel.JsonWebTokens.dll",
        "lib/net8.0/Microsoft.IdentityModel.JsonWebTokens.xml",
        "lib/net9.0/Microsoft.IdentityModel.JsonWebTokens.dll",
        "lib/net9.0/Microsoft.IdentityModel.JsonWebTokens.xml",
        "lib/netstandard2.0/Microsoft.IdentityModel.JsonWebTokens.dll",
        "lib/netstandard2.0/Microsoft.IdentityModel.JsonWebTokens.xml",
        "microsoft.identitymodel.jsonwebtokens.8.1.2.nupkg.sha512",
        "microsoft.identitymodel.jsonwebtokens.nuspec"
      ]
    },
    "Microsoft.IdentityModel.Logging/8.1.2": {
      "sha512": "pEn//qKJcEXDsLHLzACFrT3a2kkpIGOXLEYkcuxjqWoeDnbeotu0LY9fF8+Ds9WWpVE9ZGlxXamT0VR8rxaQeA==",
      "type": "package",
      "path": "microsoft.identitymodel.logging/8.1.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "lib/net462/Microsoft.IdentityModel.Logging.dll",
        "lib/net462/Microsoft.IdentityModel.Logging.xml",
        "lib/net472/Microsoft.IdentityModel.Logging.dll",
        "lib/net472/Microsoft.IdentityModel.Logging.xml",
        "lib/net6.0/Microsoft.IdentityModel.Logging.dll",
        "lib/net6.0/Microsoft.IdentityModel.Logging.xml",
        "lib/net8.0/Microsoft.IdentityModel.Logging.dll",
        "lib/net8.0/Microsoft.IdentityModel.Logging.xml",
        "lib/net9.0/Microsoft.IdentityModel.Logging.dll",
        "lib/net9.0/Microsoft.IdentityModel.Logging.xml",
        "lib/netstandard2.0/Microsoft.IdentityModel.Logging.dll",
        "lib/netstandard2.0/Microsoft.IdentityModel.Logging.xml",
        "microsoft.identitymodel.logging.8.1.2.nupkg.sha512",
        "microsoft.identitymodel.logging.nuspec"
      ]
    },
    "Microsoft.IdentityModel.Protocols/7.1.2": {
      "sha512": "SydLwMRFx6EHPWJ+N6+MVaoArN1Htt92b935O3RUWPY1yUF63zEjvd3lBu79eWdZUwedP8TN2I5V9T3nackvIQ==",
      "type": "package",
      "path": "microsoft.identitymodel.protocols/7.1.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net461/Microsoft.IdentityModel.Protocols.dll",
        "lib/net461/Microsoft.IdentityModel.Protocols.xml",
        "lib/net462/Microsoft.IdentityModel.Protocols.dll",
        "lib/net462/Microsoft.IdentityModel.Protocols.xml",
        "lib/net472/Microsoft.IdentityModel.Protocols.dll",
        "lib/net472/Microsoft.IdentityModel.Protocols.xml",
        "lib/net6.0/Microsoft.IdentityModel.Protocols.dll",
        "lib/net6.0/Microsoft.IdentityModel.Protocols.xml",
        "lib/net8.0/Microsoft.IdentityModel.Protocols.dll",
        "lib/net8.0/Microsoft.IdentityModel.Protocols.xml",
        "lib/netstandard2.0/Microsoft.IdentityModel.Protocols.dll",
        "lib/netstandard2.0/Microsoft.IdentityModel.Protocols.xml",
        "microsoft.identitymodel.protocols.7.1.2.nupkg.sha512",
        "microsoft.identitymodel.protocols.nuspec"
      ]
    },
    "Microsoft.IdentityModel.Protocols.OpenIdConnect/7.1.2": {
      "sha512": "6lHQoLXhnMQ42mGrfDkzbIOR3rzKM1W1tgTeMPLgLCqwwGw0d96xFi/UiX/fYsu7d6cD5MJiL3+4HuI8VU+sVQ==",
      "type": "package",
      "path": "microsoft.identitymodel.protocols.openidconnect/7.1.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net461/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll",
        "lib/net461/Microsoft.IdentityModel.Protocols.OpenIdConnect.xml",
        "lib/net462/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll",
        "lib/net462/Microsoft.IdentityModel.Protocols.OpenIdConnect.xml",
        "lib/net472/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll",
        "lib/net472/Microsoft.IdentityModel.Protocols.OpenIdConnect.xml",
        "lib/net6.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll",
        "lib/net6.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.xml",
        "lib/net8.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll",
        "lib/net8.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.xml",
        "lib/netstandard2.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.dll",
        "lib/netstandard2.0/Microsoft.IdentityModel.Protocols.OpenIdConnect.xml",
        "microsoft.identitymodel.protocols.openidconnect.7.1.2.nupkg.sha512",
        "microsoft.identitymodel.protocols.openidconnect.nuspec"
      ]
    },
    "Microsoft.IdentityModel.Tokens/8.1.2": {
      "sha512": "ZSzGsAA3BY20XHnsp8OjrHFtpd+pQtiu4UJDjPtXwCtEzcE5CjWP/8iZEJXy5AxVEFB0z6EwLSN+T1Fsdpjifw==",
      "type": "package",
      "path": "microsoft.identitymodel.tokens/8.1.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "lib/net462/Microsoft.IdentityModel.Tokens.dll",
        "lib/net462/Microsoft.IdentityModel.Tokens.xml",
        "lib/net472/Microsoft.IdentityModel.Tokens.dll",
        "lib/net472/Microsoft.IdentityModel.Tokens.xml",
        "lib/net6.0/Microsoft.IdentityModel.Tokens.dll",
        "lib/net6.0/Microsoft.IdentityModel.Tokens.xml",
        "lib/net8.0/Microsoft.IdentityModel.Tokens.dll",
        "lib/net8.0/Microsoft.IdentityModel.Tokens.xml",
        "lib/net9.0/Microsoft.IdentityModel.Tokens.dll",
        "lib/net9.0/Microsoft.IdentityModel.Tokens.xml",
        "lib/netstandard2.0/Microsoft.IdentityModel.Tokens.dll",
        "lib/netstandard2.0/Microsoft.IdentityModel.Tokens.xml",
        "microsoft.identitymodel.tokens.8.1.2.nupkg.sha512",
        "microsoft.identitymodel.tokens.nuspec"
      ]
    },
    "Microsoft.OpenApi/1.6.14": {
      "sha512": "tTaBT8qjk3xINfESyOPE2rIellPvB7qpVqiWiyA/lACVvz+xOGiXhFUfohcx82NLbi5avzLW0lx+s6oAqQijfw==",
      "type": "package",
      "path": "microsoft.openapi/1.6.14",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "lib/netstandard2.0/Microsoft.OpenApi.dll",
        "lib/netstandard2.0/Microsoft.OpenApi.pdb",
        "lib/netstandard2.0/Microsoft.OpenApi.xml",
        "microsoft.openapi.1.6.14.nupkg.sha512",
        "microsoft.openapi.nuspec"
      ]
    },
    "Newtonsoft.Json/13.0.3": {
      "sha512": "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ==",
      "type": "package",
      "path": "newtonsoft.json/13.0.3",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "LICENSE.md",
        "README.md",
        "lib/net20/Newtonsoft.Json.dll",
        "lib/net20/Newtonsoft.Json.xml",
        "lib/net35/Newtonsoft.Json.dll",
        "lib/net35/Newtonsoft.Json.xml",
        "lib/net40/Newtonsoft.Json.dll",
        "lib/net40/Newtonsoft.Json.xml",
        "lib/net45/Newtonsoft.Json.dll",
        "lib/net45/Newtonsoft.Json.xml",
        "lib/net6.0/Newtonsoft.Json.dll",
        "lib/net6.0/Newtonsoft.Json.xml",
        "lib/netstandard1.0/Newtonsoft.Json.dll",
        "lib/netstandard1.0/Newtonsoft.Json.xml",
        "lib/netstandard1.3/Newtonsoft.Json.dll",
        "lib/netstandard1.3/Newtonsoft.Json.xml",
        "lib/netstandard2.0/Newtonsoft.Json.dll",
        "lib/netstandard2.0/Newtonsoft.Json.xml",
        "newtonsoft.json.13.0.3.nupkg.sha512",
        "newtonsoft.json.nuspec",
        "packageIcon.png"
      ]
    },
    "Pipelines.Sockets.Unofficial/2.2.8": {
      "sha512": "zG2FApP5zxSx6OcdJQLbZDk2AVlN2BNQD6MorwIfV6gVj0RRxWPEp2LXAxqDGZqeNV1Zp0BNPcNaey/GXmTdvQ==",
      "type": "package",
      "path": "pipelines.sockets.unofficial/2.2.8",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net461/Pipelines.Sockets.Unofficial.dll",
        "lib/net461/Pipelines.Sockets.Unofficial.xml",
        "lib/net472/Pipelines.Sockets.Unofficial.dll",
        "lib/net472/Pipelines.Sockets.Unofficial.xml",
        "lib/net5.0/Pipelines.Sockets.Unofficial.dll",
        "lib/net5.0/Pipelines.Sockets.Unofficial.xml",
        "lib/netcoreapp3.1/Pipelines.Sockets.Unofficial.dll",
        "lib/netcoreapp3.1/Pipelines.Sockets.Unofficial.xml",
        "lib/netstandard2.0/Pipelines.Sockets.Unofficial.dll",
        "lib/netstandard2.0/Pipelines.Sockets.Unofficial.xml",
        "lib/netstandard2.1/Pipelines.Sockets.Unofficial.dll",
        "lib/netstandard2.1/Pipelines.Sockets.Unofficial.xml",
        "pipelines.sockets.unofficial.2.2.8.nupkg.sha512",
        "pipelines.sockets.unofficial.nuspec"
      ]
    },
    "SQLitePCLRaw.bundle_e_sqlite3/2.1.6": {
      "sha512": "BmAf6XWt4TqtowmiWe4/5rRot6GerAeklmOPfviOvwLoF5WwgxcJHAxZtySuyW9r9w+HLILnm8VfJFLCUJYW8A==",
      "type": "package",
      "path": "sqlitepclraw.bundle_e_sqlite3/2.1.6",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/monoandroid90/SQLitePCLRaw.batteries_v2.dll",
        "lib/net461/SQLitePCLRaw.batteries_v2.dll",
        "lib/net6.0-android31.0/SQLitePCLRaw.batteries_v2.dll",
        "lib/net6.0-android31.0/SQLitePCLRaw.batteries_v2.xml",
        "lib/net6.0-ios14.0/SQLitePCLRaw.batteries_v2.dll",
        "lib/net6.0-ios14.2/SQLitePCLRaw.batteries_v2.dll",
        "lib/net6.0-tvos10.0/SQLitePCLRaw.batteries_v2.dll",
        "lib/netstandard2.0/SQLitePCLRaw.batteries_v2.dll",
        "lib/xamarinios10/SQLitePCLRaw.batteries_v2.dll",
        "sqlitepclraw.bundle_e_sqlite3.2.1.6.nupkg.sha512",
        "sqlitepclraw.bundle_e_sqlite3.nuspec"
      ]
    },
    "SQLitePCLRaw.core/2.1.6": {
      "sha512": "wO6v9GeMx9CUngAet8hbO7xdm+M42p1XeJq47ogyRoYSvNSp0NGLI+MgC0bhrMk9C17MTVFlLiN6ylyExLCc5w==",
      "type": "package",
      "path": "sqlitepclraw.core/2.1.6",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/netstandard2.0/SQLitePCLRaw.core.dll",
        "sqlitepclraw.core.2.1.6.nupkg.sha512",
        "sqlitepclraw.core.nuspec"
      ]
    },
    "SQLitePCLRaw.lib.e_sqlite3/2.1.6": {
      "sha512": "2ObJJLkIUIxRpOUlZNGuD4rICpBnrBR5anjyfUFQep4hMOIeqW+XGQYzrNmHSVz5xSWZ3klSbh7sFR6UyDj68Q==",
      "type": "package",
      "path": "sqlitepclraw.lib.e_sqlite3/2.1.6",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "buildTransitive/net461/SQLitePCLRaw.lib.e_sqlite3.targets",
        "buildTransitive/net6.0/SQLitePCLRaw.lib.e_sqlite3.targets",
        "buildTransitive/net7.0/SQLitePCLRaw.lib.e_sqlite3.targets",
        "buildTransitive/net8.0/SQLitePCLRaw.lib.e_sqlite3.targets",
        "lib/net461/_._",
        "lib/netstandard2.0/_._",
        "runtimes/browser-wasm/nativeassets/net6.0/e_sqlite3.a",
        "runtimes/browser-wasm/nativeassets/net7.0/e_sqlite3.a",
        "runtimes/browser-wasm/nativeassets/net8.0/e_sqlite3.a",
        "runtimes/linux-arm/native/libe_sqlite3.so",
        "runtimes/linux-arm64/native/libe_sqlite3.so",
        "runtimes/linux-armel/native/libe_sqlite3.so",
        "runtimes/linux-mips64/native/libe_sqlite3.so",
        "runtimes/linux-musl-arm/native/libe_sqlite3.so",
        "runtimes/linux-musl-arm64/native/libe_sqlite3.so",
        "runtimes/linux-musl-x64/native/libe_sqlite3.so",
        "runtimes/linux-ppc64le/native/libe_sqlite3.so",
        "runtimes/linux-s390x/native/libe_sqlite3.so",
        "runtimes/linux-x64/native/libe_sqlite3.so",
        "runtimes/linux-x86/native/libe_sqlite3.so",
        "runtimes/maccatalyst-arm64/native/libe_sqlite3.dylib",
        "runtimes/maccatalyst-x64/native/libe_sqlite3.dylib",
        "runtimes/osx-arm64/native/libe_sqlite3.dylib",
        "runtimes/osx-x64/native/libe_sqlite3.dylib",
        "runtimes/win-arm/native/e_sqlite3.dll",
        "runtimes/win-arm64/native/e_sqlite3.dll",
        "runtimes/win-x64/native/e_sqlite3.dll",
        "runtimes/win-x86/native/e_sqlite3.dll",
        "runtimes/win10-arm/nativeassets/uap10.0/e_sqlite3.dll",
        "runtimes/win10-arm64/nativeassets/uap10.0/e_sqlite3.dll",
        "runtimes/win10-x64/nativeassets/uap10.0/e_sqlite3.dll",
        "runtimes/win10-x86/nativeassets/uap10.0/e_sqlite3.dll",
        "sqlitepclraw.lib.e_sqlite3.2.1.6.nupkg.sha512",
        "sqlitepclraw.lib.e_sqlite3.nuspec"
      ]
    },
    "SQLitePCLRaw.provider.e_sqlite3/2.1.6": {
      "sha512": "PQ2Oq3yepLY4P7ll145P3xtx2bX8xF4PzaKPRpw9jZlKvfe4LE/saAV82inND9usn1XRpmxXk7Lal3MTI+6CNg==",
      "type": "package",
      "path": "sqlitepclraw.provider.e_sqlite3/2.1.6",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net6.0-windows7.0/SQLitePCLRaw.provider.e_sqlite3.dll",
        "lib/net6.0/SQLitePCLRaw.provider.e_sqlite3.dll",
        "lib/netstandard2.0/SQLitePCLRaw.provider.e_sqlite3.dll",
        "sqlitepclraw.provider.e_sqlite3.2.1.6.nupkg.sha512",
        "sqlitepclraw.provider.e_sqlite3.nuspec"
      ]
    },
    "StackExchange.Redis/2.8.16": {
      "sha512": "WaoulkOqOC9jHepca3JZKFTqndCWab5uYS7qCzmiQDlrTkFaDN7eLSlEfHycBxipRnQY9ppZM7QSsWAwUEGblw==",
      "type": "package",
      "path": "stackexchange.redis/2.8.16",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net461/StackExchange.Redis.dll",
        "lib/net461/StackExchange.Redis.xml",
        "lib/net472/StackExchange.Redis.dll",
        "lib/net472/StackExchange.Redis.xml",
        "lib/net6.0/StackExchange.Redis.dll",
        "lib/net6.0/StackExchange.Redis.xml",
        "lib/netcoreapp3.1/StackExchange.Redis.dll",
        "lib/netcoreapp3.1/StackExchange.Redis.xml",
        "lib/netstandard2.0/StackExchange.Redis.dll",
        "lib/netstandard2.0/StackExchange.Redis.xml",
        "stackexchange.redis.2.8.16.nupkg.sha512",
        "stackexchange.redis.nuspec"
      ]
    },
    "Stripe.net/46.2.1": {
      "sha512": "lOtIJRi/5Ct6AvhDug1d+F4zLX4dFIaWiIqG7vQ3DVOiclF/UMSKd0s8jVevNLyKO0d7q1SdfZ43x2t4+9+VeA==",
      "type": "package",
      "path": "stripe.net/46.2.1",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "LICENSE",
        "README.md",
        "icon.png",
        "lib/net461/Stripe.net.dll",
        "lib/net461/Stripe.net.xml",
        "lib/net5.0/Stripe.net.dll",
        "lib/net5.0/Stripe.net.xml",
        "lib/net6.0/Stripe.net.dll",
        "lib/net6.0/Stripe.net.xml",
        "lib/net7.0/Stripe.net.dll",
        "lib/net7.0/Stripe.net.xml",
        "lib/net8.0/Stripe.net.dll",
        "lib/net8.0/Stripe.net.xml",
        "lib/netcoreapp3.1/Stripe.net.dll",
        "lib/netcoreapp3.1/Stripe.net.xml",
        "lib/netstandard2.0/Stripe.net.dll",
        "lib/netstandard2.0/Stripe.net.xml",
        "stripe.net.46.2.1.nupkg.sha512",
        "stripe.net.nuspec"
      ]
    },
    "Swashbuckle.AspNetCore/6.9.0": {
      "sha512": "lvI+XHF21tkwXd2nDCLGJsdhdUYsY3Ax2fWUlvw81Oa6EedtnIAf5tThy8ZnPcz/9/TwsLgjgtX9ifOCIjbEPA==",
      "type": "package",
      "path": "swashbuckle.aspnetcore/6.9.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "build/Swashbuckle.AspNetCore.props",
        "buildMultiTargeting/Swashbuckle.AspNetCore.props",
        "swashbuckle.aspnetcore.6.9.0.nupkg.sha512",
        "swashbuckle.aspnetcore.nuspec"
      ]
    },
    "Swashbuckle.AspNetCore.Swagger/6.9.0": {
      "sha512": "P316kpxx5DnDvJwNWW8iTAXkh9DVenAxFGe9v4OUS0gil+vitH7F1feXhCtVeHN/616EFNTMh4pV2lcr9kkw/w==",
      "type": "package",
      "path": "swashbuckle.aspnetcore.swagger/6.9.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net5.0/Swashbuckle.AspNetCore.Swagger.dll",
        "lib/net5.0/Swashbuckle.AspNetCore.Swagger.pdb",
        "lib/net5.0/Swashbuckle.AspNetCore.Swagger.xml",
        "lib/net6.0/Swashbuckle.AspNetCore.Swagger.dll",
        "lib/net6.0/Swashbuckle.AspNetCore.Swagger.pdb",
        "lib/net6.0/Swashbuckle.AspNetCore.Swagger.xml",
        "lib/net7.0/Swashbuckle.AspNetCore.Swagger.dll",
        "lib/net7.0/Swashbuckle.AspNetCore.Swagger.pdb",
        "lib/net7.0/Swashbuckle.AspNetCore.Swagger.xml",
        "lib/net8.0/Swashbuckle.AspNetCore.Swagger.dll",
        "lib/net8.0/Swashbuckle.AspNetCore.Swagger.pdb",
        "lib/net8.0/Swashbuckle.AspNetCore.Swagger.xml",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.Swagger.dll",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.Swagger.pdb",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.Swagger.xml",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.Swagger.dll",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.Swagger.pdb",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.Swagger.xml",
        "package-readme.md",
        "swashbuckle.aspnetcore.swagger.6.9.0.nupkg.sha512",
        "swashbuckle.aspnetcore.swagger.nuspec"
      ]
    },
    "Swashbuckle.AspNetCore.SwaggerGen/6.9.0": {
      "sha512": "FjeMR3fBzwVc5plfYjoHw9ptf8SOWMupvO9X35J5EgzT3L9dRqSxa+cBKzL8PwCyemY0xNrggQSB5+MFWx1axg==",
      "type": "package",
      "path": "swashbuckle.aspnetcore.swaggergen/6.9.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net5.0/Swashbuckle.AspNetCore.SwaggerGen.dll",
        "lib/net5.0/Swashbuckle.AspNetCore.SwaggerGen.pdb",
        "lib/net5.0/Swashbuckle.AspNetCore.SwaggerGen.xml",
        "lib/net6.0/Swashbuckle.AspNetCore.SwaggerGen.dll",
        "lib/net6.0/Swashbuckle.AspNetCore.SwaggerGen.pdb",
        "lib/net6.0/Swashbuckle.AspNetCore.SwaggerGen.xml",
        "lib/net7.0/Swashbuckle.AspNetCore.SwaggerGen.dll",
        "lib/net7.0/Swashbuckle.AspNetCore.SwaggerGen.pdb",
        "lib/net7.0/Swashbuckle.AspNetCore.SwaggerGen.xml",
        "lib/net8.0/Swashbuckle.AspNetCore.SwaggerGen.dll",
        "lib/net8.0/Swashbuckle.AspNetCore.SwaggerGen.pdb",
        "lib/net8.0/Swashbuckle.AspNetCore.SwaggerGen.xml",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.SwaggerGen.dll",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.SwaggerGen.pdb",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.SwaggerGen.xml",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.SwaggerGen.dll",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.SwaggerGen.pdb",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.SwaggerGen.xml",
        "package-readme.md",
        "swashbuckle.aspnetcore.swaggergen.6.9.0.nupkg.sha512",
        "swashbuckle.aspnetcore.swaggergen.nuspec"
      ]
    },
    "Swashbuckle.AspNetCore.SwaggerUI/6.9.0": {
      "sha512": "0OxlWBFLl2gUESZX/K7QCTz9KctKy0VxHTvLIBcyWGD4z/fv5MCMW02qzYGcReLJr4yBnNDRzApKtLh6oBpe9A==",
      "type": "package",
      "path": "swashbuckle.aspnetcore.swaggerui/6.9.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "lib/net5.0/Swashbuckle.AspNetCore.SwaggerUI.dll",
        "lib/net5.0/Swashbuckle.AspNetCore.SwaggerUI.pdb",
        "lib/net5.0/Swashbuckle.AspNetCore.SwaggerUI.xml",
        "lib/net6.0/Swashbuckle.AspNetCore.SwaggerUI.dll",
        "lib/net6.0/Swashbuckle.AspNetCore.SwaggerUI.pdb",
        "lib/net6.0/Swashbuckle.AspNetCore.SwaggerUI.xml",
        "lib/net7.0/Swashbuckle.AspNetCore.SwaggerUI.dll",
        "lib/net7.0/Swashbuckle.AspNetCore.SwaggerUI.pdb",
        "lib/net7.0/Swashbuckle.AspNetCore.SwaggerUI.xml",
        "lib/net8.0/Swashbuckle.AspNetCore.SwaggerUI.dll",
        "lib/net8.0/Swashbuckle.AspNetCore.SwaggerUI.pdb",
        "lib/net8.0/Swashbuckle.AspNetCore.SwaggerUI.xml",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.SwaggerUI.dll",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.SwaggerUI.pdb",
        "lib/netcoreapp3.0/Swashbuckle.AspNetCore.SwaggerUI.xml",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.SwaggerUI.dll",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.SwaggerUI.pdb",
        "lib/netstandard2.0/Swashbuckle.AspNetCore.SwaggerUI.xml",
        "package-readme.md",
        "swashbuckle.aspnetcore.swaggerui.6.9.0.nupkg.sha512",
        "swashbuckle.aspnetcore.swaggerui.nuspec"
      ]
    },
    "System.Configuration.ConfigurationManager/8.0.0": {
      "sha512": "JlYi9XVvIREURRUlGMr1F6vOFLk7YSY4p1vHo4kX3tQ0AGrjqlRWHDi66ImHhy6qwXBG3BJ6Y1QlYQ+Qz6Xgww==",
      "type": "package",
      "path": "system.configuration.configurationmanager/8.0.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/System.Configuration.ConfigurationManager.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/System.Configuration.ConfigurationManager.targets",
        "lib/net462/System.Configuration.ConfigurationManager.dll",
        "lib/net462/System.Configuration.ConfigurationManager.xml",
        "lib/net6.0/System.Configuration.ConfigurationManager.dll",
        "lib/net6.0/System.Configuration.ConfigurationManager.xml",
        "lib/net7.0/System.Configuration.ConfigurationManager.dll",
        "lib/net7.0/System.Configuration.ConfigurationManager.xml",
        "lib/net8.0/System.Configuration.ConfigurationManager.dll",
        "lib/net8.0/System.Configuration.ConfigurationManager.xml",
        "lib/netstandard2.0/System.Configuration.ConfigurationManager.dll",
        "lib/netstandard2.0/System.Configuration.ConfigurationManager.xml",
        "system.configuration.configurationmanager.8.0.0.nupkg.sha512",
        "system.configuration.configurationmanager.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "System.Diagnostics.EventLog/8.0.0": {
      "sha512": "fdYxcRjQqTTacKId/2IECojlDSFvp7LP5N78+0z/xH7v/Tuw5ZAxu23Y6PTCRinqyu2ePx+Gn1098NC6jM6d+A==",
      "type": "package",
      "path": "system.diagnostics.eventlog/8.0.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/System.Diagnostics.EventLog.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/System.Diagnostics.EventLog.targets",
        "lib/net462/System.Diagnostics.EventLog.dll",
        "lib/net462/System.Diagnostics.EventLog.xml",
        "lib/net6.0/System.Diagnostics.EventLog.dll",
        "lib/net6.0/System.Diagnostics.EventLog.xml",
        "lib/net7.0/System.Diagnostics.EventLog.dll",
        "lib/net7.0/System.Diagnostics.EventLog.xml",
        "lib/net8.0/System.Diagnostics.EventLog.dll",
        "lib/net8.0/System.Diagnostics.EventLog.xml",
        "lib/netstandard2.0/System.Diagnostics.EventLog.dll",
        "lib/netstandard2.0/System.Diagnostics.EventLog.xml",
        "runtimes/win/lib/net6.0/System.Diagnostics.EventLog.Messages.dll",
        "runtimes/win/lib/net6.0/System.Diagnostics.EventLog.dll",
        "runtimes/win/lib/net6.0/System.Diagnostics.EventLog.xml",
        "runtimes/win/lib/net7.0/System.Diagnostics.EventLog.Messages.dll",
        "runtimes/win/lib/net7.0/System.Diagnostics.EventLog.dll",
        "runtimes/win/lib/net7.0/System.Diagnostics.EventLog.xml",
        "runtimes/win/lib/net8.0/System.Diagnostics.EventLog.Messages.dll",
        "runtimes/win/lib/net8.0/System.Diagnostics.EventLog.dll",
        "runtimes/win/lib/net8.0/System.Diagnostics.EventLog.xml",
        "system.diagnostics.eventlog.8.0.0.nupkg.sha512",
        "system.diagnostics.eventlog.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "System.IdentityModel.Tokens.Jwt/8.1.2": {
      "sha512": "UoidlNYjML1ZbV5s8bLP84VpxDzv8uhHzyt5YkZwqLmFTmtOQheNuTKpR/5UWmO5Ka4JT3kVmhUNq5Li733wTg==",
      "type": "package",
      "path": "system.identitymodel.tokens.jwt/8.1.2",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "README.md",
        "lib/net462/System.IdentityModel.Tokens.Jwt.dll",
        "lib/net462/System.IdentityModel.Tokens.Jwt.xml",
        "lib/net472/System.IdentityModel.Tokens.Jwt.dll",
        "lib/net472/System.IdentityModel.Tokens.Jwt.xml",
        "lib/net6.0/System.IdentityModel.Tokens.Jwt.dll",
        "lib/net6.0/System.IdentityModel.Tokens.Jwt.xml",
        "lib/net8.0/System.IdentityModel.Tokens.Jwt.dll",
        "lib/net8.0/System.IdentityModel.Tokens.Jwt.xml",
        "lib/net9.0/System.IdentityModel.Tokens.Jwt.dll",
        "lib/net9.0/System.IdentityModel.Tokens.Jwt.xml",
        "lib/netstandard2.0/System.IdentityModel.Tokens.Jwt.dll",
        "lib/netstandard2.0/System.IdentityModel.Tokens.Jwt.xml",
        "system.identitymodel.tokens.jwt.8.1.2.nupkg.sha512",
        "system.identitymodel.tokens.jwt.nuspec"
      ]
    },
    "System.IO.Pipelines/5.0.1": {
      "sha512": "qEePWsaq9LoEEIqhbGe6D5J8c9IqQOUuTzzV6wn1POlfdLkJliZY3OlB0j0f17uMWlqZYjH7txj+2YbyrIA8Yg==",
      "type": "package",
      "path": "system.io.pipelines/5.0.1",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/net461/System.IO.Pipelines.dll",
        "lib/net461/System.IO.Pipelines.xml",
        "lib/netcoreapp3.0/System.IO.Pipelines.dll",
        "lib/netcoreapp3.0/System.IO.Pipelines.xml",
        "lib/netstandard1.3/System.IO.Pipelines.dll",
        "lib/netstandard1.3/System.IO.Pipelines.xml",
        "lib/netstandard2.0/System.IO.Pipelines.dll",
        "lib/netstandard2.0/System.IO.Pipelines.xml",
        "ref/netcoreapp2.0/System.IO.Pipelines.dll",
        "ref/netcoreapp2.0/System.IO.Pipelines.xml",
        "system.io.pipelines.5.0.1.nupkg.sha512",
        "system.io.pipelines.nuspec",
        "useSharedDesignerContext.txt",
        "version.txt"
      ]
    },
    "System.Memory/4.5.3": {
      "sha512": "3oDzvc/zzetpTKWMShs1AADwZjQ/36HnsufHRPcOjyRAAMLDlu2iD33MBI2opxnezcVUtXyqDXXjoFMOU9c7SA==",
      "type": "package",
      "path": "system.memory/4.5.3",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "LICENSE.TXT",
        "THIRD-PARTY-NOTICES.TXT",
        "lib/netcoreapp2.1/_._",
        "lib/netstandard1.1/System.Memory.dll",
        "lib/netstandard1.1/System.Memory.xml",
        "lib/netstandard2.0/System.Memory.dll",
        "lib/netstandard2.0/System.Memory.xml",
        "ref/netcoreapp2.1/_._",
        "system.memory.4.5.3.nupkg.sha512",
        "system.memory.nuspec",
        "useSharedDesignerContext.txt",
        "version.txt"
      ]
    },
    "System.Security.Cryptography.ProtectedData/8.0.0": {
      "sha512": "+TUFINV2q2ifyXauQXRwy4CiBhqvDEDZeVJU7qfxya4aRYOKzVBpN+4acx25VcPB9ywUN6C0n8drWl110PhZEg==",
      "type": "package",
      "path": "system.security.cryptography.protecteddata/8.0.0",
      "files": [
        ".nupkg.metadata",
        ".signature.p7s",
        "Icon.png",
        "LICENSE.TXT",
        "PACKAGE.md",
        "THIRD-PARTY-NOTICES.TXT",
        "buildTransitive/net461/System.Security.Cryptography.ProtectedData.targets",
        "buildTransitive/net462/_._",
        "buildTransitive/net6.0/_._",
        "buildTransitive/netcoreapp2.0/System.Security.Cryptography.ProtectedData.targets",
        "lib/MonoAndroid10/_._",
        "lib/MonoTouch10/_._",
        "lib/net462/System.Security.Cryptography.ProtectedData.dll",
        "lib/net462/System.Security.Cryptography.ProtectedData.xml",
        "lib/net6.0/System.Security.Cryptography.ProtectedData.dll",
        "lib/net6.0/System.Security.Cryptography.ProtectedData.xml",
        "lib/net7.0/System.Security.Cryptography.ProtectedData.dll",
        "lib/net7.0/System.Security.Cryptography.ProtectedData.xml",
        "lib/net8.0/System.Security.Cryptography.ProtectedData.dll",
        "lib/net8.0/System.Security.Cryptography.ProtectedData.xml",
        "lib/netstandard2.0/System.Security.Cryptography.ProtectedData.dll",
        "lib/netstandard2.0/System.Security.Cryptography.ProtectedData.xml",
        "lib/xamarinios10/_._",
        "lib/xamarinmac20/_._",
        "lib/xamarintvos10/_._",
        "lib/xamarinwatchos10/_._",
        "system.security.cryptography.protecteddata.8.0.0.nupkg.sha512",
        "system.security.cryptography.protecteddata.nuspec",
        "useSharedDesignerContext.txt"
      ]
    },
    "Kitab.DataAccess/1.0.0": {
      "type": "project",
      "path": "../Kitab.DataAccess/Kitab.DataAccess.csproj",
      "msbuildProject": "../Kitab.DataAccess/Kitab.DataAccess.csproj"
    },
    "Kitab.DataTransferObject/1.0.0": {
      "type": "project",
      "path": "../Kitab.DataTransferObject/Kitab.DataTransferObject.csproj",
      "msbuildProject": "../Kitab.DataTransferObject/Kitab.DataTransferObject.csproj"
    },
    "Kitab.Entities/1.0.0": {
      "type": "project",
      "path": "../Kitab.Entities/Kitab.Entities.csproj",
      "msbuildProject": "../Kitab.Entities/Kitab.Entities.csproj"
    },
    "Kitab.Util/1.0.0": {
      "type": "project",
      "path": "../Kitab.Util/Kitab.Util.csproj",
      "msbuildProject": "../Kitab.Util/Kitab.Util.csproj"
    }
  },
  "projectFileDependencyGroups": {
    "net8.0": [
      "Kitab.DataAccess >= 1.0.0",
      "Kitab.Util >= 1.0.0",
      "Microsoft.AspNetCore.Authentication.JwtBearer >= 8.0.10",
      "Microsoft.EntityFrameworkCore.Sqlite >= 8.0.10",
      "Swashbuckle.AspNetCore.SwaggerGen >= 6.9.0",
      "Swashbuckle.AspNetCore.SwaggerUI >= 6.9.0"
    ]
  },
  "packageFolders": {
    "C:\\Users\\Morty\\.nuget\\packages\\": {},
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages": {}
  },
  "project": {
    "version": "1.0.0",
    "restore": {
      "projectUniqueName": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj",
      "projectName": "Kitab.WebAPI",
      "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj",
      "packagesPath": "C:\\Users\\Morty\\.nuget\\packages\\",
      "outputPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\obj\\",
      "projectStyle": "PackageReference",
      "fallbackFolders": [
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages"
      ],
      "configFilePaths": [
        "C:\\Users\\Morty\\AppData\\Roaming\\NuGet\\NuGet.Config",
        "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.FallbackLocation.config",
        "C:\\Program Files (x86)\\NuGet\\Config\\Microsoft.VisualStudio.Offline.config"
      ],
      "originalTargetFrameworks": [
        "netcoreapp8.0"
      ],
      "sources": {
        "C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\": {},
        "C:\\Program Files\\dotnet\\library-packs": {},
        "https://api.nuget.org/v3/index.json": {}
      },
      "frameworks": {
        "net8.0": {
          "targetAlias": "netcoreapp8.0",
          "projectReferences": {
            "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj": {
              "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj"
            },
            "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj": {
              "projectPath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj"
            }
          }
        }
      },
      "warningProperties": {
        "warnAsError": [
          "NU1605"
        ]
      },
      "restoreAuditProperties": {
        "enableAudit": "true",
        "auditLevel": "low",
        "auditMode": "direct"
      }
    },
    "frameworks": {
      "net8.0": {
        "targetAlias": "netcoreapp8.0",
        "dependencies": {
          "Microsoft.AspNetCore.Authentication.JwtBearer": {
            "target": "Package",
            "version": "[8.0.10, )"
          },
          "Microsoft.EntityFrameworkCore.Sqlite": {
            "target": "Package",
            "version": "[8.0.10, )"
          },
          "Swashbuckle.AspNetCore.SwaggerGen": {
            "target": "Package",
            "version": "[6.9.0, )"
          },
          "Swashbuckle.AspNetCore.SwaggerUI": {
            "target": "Package",
            "version": "[6.9.0, )"
          }
        },
        "imports": [
          "net461",
          "net462",
          "net47",
          "net471",
          "net472",
          "net48",
          "net481"
        ],
        "assetTargetFallback": true,
        "warn": true,
        "frameworkReferences": {
          "Microsoft.AspNetCore.App": {
            "privateAssets": "none"
          },
          "Microsoft.NETCore.App": {
            "privateAssets": "all"
          }
        },
        "runtimeIdentifierGraphPath": "C:\\Program Files\\dotnet\\sdk\\8.0.403/PortableRuntimeIdentifierGraph.json"
      }
    }
  }
}
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\project.nuget.cache`:

```cache
{
  "version": 2,
  "dgSpecHash": "/z+pLo9hHK0=",
  "success": true,
  "projectFilePath": "C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj",
  "expectedPackageFiles": [
    "C:\\Users\\Morty\\.nuget\\packages\\automapper\\13.0.1\\automapper.13.0.1.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\fluentvalidation\\11.10.0\\fluentvalidation.11.10.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.aspnetcore.authentication.jwtbearer\\8.0.10\\microsoft.aspnetcore.authentication.jwtbearer.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.aspnetcore.cryptography.internal\\8.0.10\\microsoft.aspnetcore.cryptography.internal.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.aspnetcore.cryptography.keyderivation\\8.0.10\\microsoft.aspnetcore.cryptography.keyderivation.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.aspnetcore.identity.entityframeworkcore\\8.0.10\\microsoft.aspnetcore.identity.entityframeworkcore.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.bcl.timeprovider\\8.0.1\\microsoft.bcl.timeprovider.8.0.1.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.data.sqlite.core\\8.0.10\\microsoft.data.sqlite.core.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.entityframeworkcore\\8.0.10\\microsoft.entityframeworkcore.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.entityframeworkcore.abstractions\\8.0.10\\microsoft.entityframeworkcore.abstractions.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.entityframeworkcore.analyzers\\8.0.10\\microsoft.entityframeworkcore.analyzers.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.entityframeworkcore.relational\\8.0.10\\microsoft.entityframeworkcore.relational.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.entityframeworkcore.sqlite\\8.0.10\\microsoft.entityframeworkcore.sqlite.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.entityframeworkcore.sqlite.core\\8.0.10\\microsoft.entityframeworkcore.sqlite.core.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.apidescription.server\\6.0.5\\microsoft.extensions.apidescription.server.6.0.5.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.caching.abstractions\\8.0.0\\microsoft.extensions.caching.abstractions.8.0.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.caching.memory\\8.0.1\\microsoft.extensions.caching.memory.8.0.1.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.configuration.abstractions\\8.0.0\\microsoft.extensions.configuration.abstractions.8.0.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.dependencyinjection\\8.0.1\\microsoft.extensions.dependencyinjection.8.0.1.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.dependencyinjection.abstractions\\8.0.2\\microsoft.extensions.dependencyinjection.abstractions.8.0.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.dependencymodel\\8.0.2\\microsoft.extensions.dependencymodel.8.0.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.identity.core\\8.0.10\\microsoft.extensions.identity.core.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.identity.stores\\8.0.10\\microsoft.extensions.identity.stores.8.0.10.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.logging\\8.0.1\\microsoft.extensions.logging.8.0.1.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.logging.abstractions\\8.0.2\\microsoft.extensions.logging.abstractions.8.0.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.options\\8.0.2\\microsoft.extensions.options.8.0.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.extensions.primitives\\8.0.0\\microsoft.extensions.primitives.8.0.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.identitymodel.abstractions\\8.1.2\\microsoft.identitymodel.abstractions.8.1.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.identitymodel.jsonwebtokens\\8.1.2\\microsoft.identitymodel.jsonwebtokens.8.1.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.identitymodel.logging\\8.1.2\\microsoft.identitymodel.logging.8.1.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.identitymodel.protocols\\7.1.2\\microsoft.identitymodel.protocols.7.1.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.identitymodel.protocols.openidconnect\\7.1.2\\microsoft.identitymodel.protocols.openidconnect.7.1.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.identitymodel.tokens\\8.1.2\\microsoft.identitymodel.tokens.8.1.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\microsoft.openapi\\1.6.14\\microsoft.openapi.1.6.14.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\newtonsoft.json\\13.0.3\\newtonsoft.json.13.0.3.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\pipelines.sockets.unofficial\\2.2.8\\pipelines.sockets.unofficial.2.2.8.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\sqlitepclraw.bundle_e_sqlite3\\2.1.6\\sqlitepclraw.bundle_e_sqlite3.2.1.6.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\sqlitepclraw.core\\2.1.6\\sqlitepclraw.core.2.1.6.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\sqlitepclraw.lib.e_sqlite3\\2.1.6\\sqlitepclraw.lib.e_sqlite3.2.1.6.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\sqlitepclraw.provider.e_sqlite3\\2.1.6\\sqlitepclraw.provider.e_sqlite3.2.1.6.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\stackexchange.redis\\2.8.16\\stackexchange.redis.2.8.16.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\stripe.net\\46.2.1\\stripe.net.46.2.1.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\swashbuckle.aspnetcore\\6.9.0\\swashbuckle.aspnetcore.6.9.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\swashbuckle.aspnetcore.swagger\\6.9.0\\swashbuckle.aspnetcore.swagger.6.9.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\swashbuckle.aspnetcore.swaggergen\\6.9.0\\swashbuckle.aspnetcore.swaggergen.6.9.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\swashbuckle.aspnetcore.swaggerui\\6.9.0\\swashbuckle.aspnetcore.swaggerui.6.9.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\system.configuration.configurationmanager\\8.0.0\\system.configuration.configurationmanager.8.0.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\system.diagnostics.eventlog\\8.0.0\\system.diagnostics.eventlog.8.0.0.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\system.identitymodel.tokens.jwt\\8.1.2\\system.identitymodel.tokens.jwt.8.1.2.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\system.io.pipelines\\5.0.1\\system.io.pipelines.5.0.1.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\system.memory\\4.5.3\\system.memory.4.5.3.nupkg.sha512",
    "C:\\Users\\Morty\\.nuget\\packages\\system.security.cryptography.protecteddata\\8.0.0\\system.security.cryptography.protecteddata.8.0.0.nupkg.sha512"
  ],
  "logs": []
}
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\project.packagespec.json`:

```json
﻿"restore":{"projectUniqueName":"C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj","projectName":"Kitab.WebAPI","projectPath":"C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\Kitab.WebAPI.csproj","outputPath":"C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.API\\obj\\","projectStyle":"PackageReference","fallbackFolders":["C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\NuGetPackages"],"originalTargetFrameworks":["netcoreapp8.0"],"sources":{"C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\":{},"C:\\Program Files\\dotnet\\library-packs":{},"https://api.nuget.org/v3/index.json":{}},"frameworks":{"net8.0":{"targetAlias":"netcoreapp8.0","projectReferences":{"C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj":{"projectPath":"C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.DataAccess\\Kitab.DataAccess.csproj"},"C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj":{"projectPath":"C:\\Users\\Morty\\Desktop\\Kitab-master\\Kitab.Util\\Kitab.Util.csproj"}}}},"warningProperties":{"warnAsError":["NU1605"]},"restoreAuditProperties":{"enableAudit":"true","auditLevel":"low","auditMode":"direct"}}"frameworks":{"net8.0":{"targetAlias":"netcoreapp8.0","dependencies":{"Microsoft.AspNetCore.Authentication.JwtBearer":{"target":"Package","version":"[8.0.10, )"},"Microsoft.EntityFrameworkCore.Sqlite":{"target":"Package","version":"[8.0.10, )"},"Swashbuckle.AspNetCore.SwaggerGen":{"target":"Package","version":"[6.9.0, )"},"Swashbuckle.AspNetCore.SwaggerUI":{"target":"Package","version":"[6.9.0, )"}},"imports":["net461","net462","net47","net471","net472","net48","net481"],"assetTargetFallback":true,"warn":true,"frameworkReferences":{"Microsoft.AspNetCore.App":{"privateAssets":"none"},"Microsoft.NETCore.App":{"privateAssets":"all"}},"runtimeIdentifierGraphPath":"C:\\Program Files\\dotnet\\sdk\\8.0.403/PortableRuntimeIdentifierGraph.json"}}
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.AssemblyInfo.cs`:

```cs
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

using System;
using System.Reflection;

[assembly: System.Reflection.AssemblyCompanyAttribute("Kitab.WebAPI")]
[assembly: System.Reflection.AssemblyConfigurationAttribute("Release")]
[assembly: System.Reflection.AssemblyFileVersionAttribute("1.0.0.0")]
[assembly: System.Reflection.AssemblyInformationalVersionAttribute("1.0.0")]
[assembly: System.Reflection.AssemblyProductAttribute("Kitab.WebAPI")]
[assembly: System.Reflection.AssemblyTitleAttribute("Kitab.WebAPI")]
[assembly: System.Reflection.AssemblyVersionAttribute("1.0.0.0")]

// Generated by the MSBuild WriteCodeFragment class.


```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.AssemblyInfoInputs.cache`:

```cache
39b3777ec3e89fbb0d753d577b476f93a3e3f8bc6da5d95027bd62af1ebbf7b1

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.csproj.CoreCompileInputs.cache`:

```cache
d341aae26089c94318563a777349d3cd9ff161470caf5d098ff54bfc7ecf191f

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.csproj.FileListAbsolute.txt`:

```txt
C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.csproj.AssemblyReference.cache
C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.GeneratedMSBuildEditorConfig.editorconfig
C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.AssemblyInfoInputs.cache
C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.AssemblyInfo.cs
C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.csproj.CoreCompileInputs.cache
C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.MvcApplicationPartsAssemblyInfo.cache

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\Release\netcoreapp8.0\Kitab.WebAPI.GeneratedMSBuildEditorConfig.editorconfig`:

```editorconfig
is_global = true
build_property.TargetFramework = netcoreapp8.0
build_property.TargetPlatformMinVersion = 
build_property.UsingMicrosoftNETSdkWeb = true
build_property.ProjectTypeGuids = 
build_property.InvariantGlobalization = 
build_property.PlatformNeutralAssembly = 
build_property.EnforceExtendedAnalyzerRules = 
build_property._SupportedPlatformList = Linux,macOS,Windows
build_property.RootNamespace = Kitab.WebAPI
build_property.RootNamespace = Kitab.WebAPI
build_property.ProjectDir = C:\Users\Morty\Desktop\Kitab-master\Kitab.API\
build_property.EnableComHosting = 
build_property.EnableGeneratedComInterfaceComImportInterop = 
build_property.RazorLangVersion = 8.0
build_property.SupportLocalizedComponentNames = 
build_property.GenerateRazorMetadataSourceChecksumAttributes = 
build_property.MSBuildProjectDirectory = C:\Users\Morty\Desktop\Kitab-master\Kitab.API
build_property._RazorSourceGeneratorDebug = 

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\rider.project.model.nuget.info`:

```info
﻿17300607479625443
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\obj\rider.project.restore.info`:

```info
﻿17300607479625443
```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Program.cs`:

```cs
using Kitab.DataAccess.Context;
using Kitab.Entities.AppUser;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace Kitab.API
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var host = CreateHostBuilder(args).Build();
            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                var loggerFactory = services.GetRequiredService<ILoggerFactory>();
                // temporary code blockes
                try
                {
                    var contextIdentity = services.GetRequiredService<DatabaseContext>();
                    var userManager = services.GetRequiredService<UserManager<AppUser>>();
                    await contextIdentity.Database.MigrateAsync();
                    await DatabaseIdentityContextSeed.SeedUserAsync(userManager, loggerFactory);

                    var context = services.GetRequiredService<DatabaseContext>();
                    await context.Database.MigrateAsync();
                    await DatabaseContextSeed.SeedAsync(context, loggerFactory);

                }
                catch (Exception ex)
                {
                    var logger = loggerFactory.CreateLogger<Program>();
                    logger.LogError(ex, "An error occured during migration");
                }
            }
            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Properties\launchSettings.json`:

```json
﻿{
  "$schema": "http://json.schemastore.org/launchsettings.json",
  "iisSettings": {
    "windowsAuthentication": false,
    "anonymousAuthentication": true,
    "iisExpress": {
      "applicationUrl": "http://localhost:63484",
      "sslPort": 0
    }
  },
  "profiles": {
    "IIS Express": {
      "commandName": "IISExpress",
      "launchBrowser": true,
      "launchUrl": "weatherforecast",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "Kitab.API": {
      "commandName": "Project",
      "launchBrowser": true,
      "launchUrl": "weatherforecast",
      "applicationUrl": "http://localhost:5000",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    }
  }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\Startup.cs`:

```cs
using AutoMapper;
using Kitab.API.Extensions;
using Kitab.DataAccess.Context;
using Kitab.Util.Mapping;
using Kitab.Util.Middleware;
using Kitab.WebAPI.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace Kitab.API
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
           
            services.AddAutoMapper(typeof(MappingProfiles));

            services.AddDbContext<DatabaseContext>();


            services.AddStartupServices();
            services.AddIdentityServices(Configuration);
            services.AddSwaggerDocumentation();
            services.AddSingleton<IConnectionMultiplexer>(c =>
            {
                var config = ConfigurationOptions.Parse(Configuration.GetConnectionString("Redis"), true);
                return ConnectionMultiplexer.Connect(config);
            });
            services.AddCors(option =>
            {
                option.AddPolicy("CorsPolicy", policy =>
                {
                    policy.AllowAnyHeader().AllowAnyMethod().WithOrigins("https://localhost:4200");
                });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseMiddleware<ExceptionMiddleware>();
            app.UseStatusCodePagesWithReExecute("/errors/{0}");
            app.UseRouting();
            app.UseStaticFiles();
            app.UseCors("CorsPolicy");
            app.UseAuthorization();
            app.UseAuthorization();
            app.UseSwaggerDocumentation();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

```

`\\?\C:\Users\Morty\Desktop\Kitab-master\Kitab.API\WeatherForecast.cs`:

```cs
using System;

namespace Kitab.API
{
    public class WeatherForecast
    {
        public DateTime Date { get; set; }

        public int TemperatureC { get; set; }

        public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);

        public string Summary { get; set; }
    }
}

```