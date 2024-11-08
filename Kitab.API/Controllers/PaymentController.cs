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
