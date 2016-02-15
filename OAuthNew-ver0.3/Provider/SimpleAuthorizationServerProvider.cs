using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace Payspan.Portal.Auth
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication
            (OAuthValidateClientAuthenticationContext context)
        {
            // validate client credentials (demo)
            // should be stored securely (salted, hashed, iterated)
            string clientKey, clientSecret;
            if (context.TryGetBasicCredentials(out clientKey, out clientSecret))
            {
                if (clientSecret == "secret")
                {
                    // need to make the client_id available for later security checks
                    context.OwinContext.Set("client_key", clientKey);
                    context.Validated();
                }
            }

            // OAuth2 supports the notion of client authentication
            // this is not used here
            //context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials
            (OAuthGrantResourceOwnerCredentialsContext context)
        {
            // validate user credentials (demo!)
            // user credentials should be stored securely (salted, iterated, hashed…)
            if (!((context.UserName == "test.test@mail.com" && context.Password == "test123")||
                (context.UserName == "jyoti.sinha@live.com" && context.Password == "test123")))
            {
                context.Rejected();
                return;
            }

            // create identity
            var id = new ClaimsIdentity("Embedded");
            id.AddClaim(new Claim("sub", context.UserName));
            id.AddClaim(new Claim("role", "user"));
            id.AddClaim(new Claim("privileges", "Admin,AccountViewer,AccountSubmit"));

            // create metadata to pass on to refresh token provider
            var props = new AuthenticationProperties(new Dictionary<string, string>
            {
                {"client_key", context.ClientId}
            });

            var ticket = new AuthenticationTicket(id, props);
            context.Validated(ticket);
        }

        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["client_key"];
            var currentClient = context.OwinContext.Get<string>("client_key");

            // enforce client binding of refresh token
            if (originalClient != currentClient)
            {
                context.Rejected();
                return;
            }

            // chance to change authentication ticket for refresh token requests
            var newId = new ClaimsIdentity(context.Ticket.Identity);
            newId.AddClaim(new Claim("newClaim", "refreshToken"));

            var newTicket = new AuthenticationTicket(newId, context.Ticket.Properties);
            context.Validated(newTicket);
        }
    }
}