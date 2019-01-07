﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// 
    /// </summary>
    public interface IByRefreshToken
    {
        /// <summary>
        /// This method should be used when you have a solution using ADAL 2.x and 
        /// caching a refresh token, and you want to migrate to MSAL.NET.
        /// During the migration process, it enables you to store in MSAL.NET token
        ///  cache an access token and refresh token corresponding to <paramref="refreshToken"/>.
        /// From there you will be able to use MSAL.NET new API, in particular
        /// AcquireTokenSilentAsync() which will renew the user token.  
        /// </summary>
        Task<AuthenticationResult> AcquireTokenByRefreshTokenAsync(string refreshToken);
    }
}