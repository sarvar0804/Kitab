using Kitab.DataAccess;
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
