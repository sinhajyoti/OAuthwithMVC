using System;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Owin;
using Payspan.Portal.Auth;

[assembly: OwinStartup(typeof (Startup))]

namespace Payspan.Portal.Auth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=316888
            // token generation
            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                // for demo purposes
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(8),
                Provider = new SimpleAuthorizationServerProvider(),
                RefreshTokenProvider = new SimpleRefreshTokenProvider()
            });
            app.UseCors(CorsOptions.AllowAll);

            // token consumption
            var config = new HttpConfiguration();
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
            WebApiConfig.Register(config);
            app.UseWebApi(config);
        }
    }
}