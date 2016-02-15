using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Payspan.Portal.Auth
{
    public class SimpleRefreshTokenProvider : IAuthenticationTokenProvider
    {
        private static readonly ConcurrentDictionary<string, AuthenticationTicket> refreshTokens =new ConcurrentDictionary<string, AuthenticationTicket>();

        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var guid = Guid.NewGuid().ToString();

            // maybe only create a handle the first time, then re-use
            refreshTokens.TryAdd(guid, context.Ticket);

            // consider storing only the hash of the handle
            context.SetToken(guid);
        }

        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            AuthenticationTicket ticket;
            if (refreshTokens.TryRemove(context.Token, out ticket))
            {
                context.SetTicket(ticket);
            }
        }

        public void Create(AuthenticationTokenCreateContext context)
        {
            while (!(CreateAsync(context).IsCompleted))
            {
            }
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            while (!(ReceiveAsync(context).IsCompleted))
            {
            }
        }
    }
}