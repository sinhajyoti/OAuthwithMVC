using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Payspan.Portal.Auth.Models;

namespace Payspan.Portal.Auth.Controllers
{
    [Authorize]
    public class IdentityController : ApiController
    {
        public IEnumerable<IdentityClaim> Get()
        {
            var principal = Request.GetRequestContext().Principal as ClaimsPrincipal;

            if (principal != null)
            {
                return from c in principal.Claims
                       select new IdentityClaim
                    {
                        Type = c.Type,
                        Value = c.Value
                    };
            }
            return null;
        }
    }
}