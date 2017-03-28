﻿//----------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.Internal.Cache;
using System.Runtime.Serialization;

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// Contains the results of one token acquisition operation.
    /// </summary>
    internal sealed class AuthenticationResult : IAuthenticationResult
    {
        private const string Oauth2AuthorizationHeader = "Bearer ";
        private readonly AccessTokenCacheItem _accessTokenCacheItem;

        internal AuthenticationResult(AccessTokenCacheItem accessTokenCacheItem, RequestContext requestContext)
        {
            _accessTokenCacheItem = accessTokenCacheItem;
            User = User.CreateFromIdToken(Internal.IdToken.Parse(accessTokenCacheItem.RawIdToken, requestContext));
        }

        /// <summary>
        /// Gets the Access Token requested.
        /// </summary>
        public string AccessToken => _accessTokenCacheItem.AccessToken;

        /// <summary>
        /// Gets the point in time in which the Access Token returned in the Token property ceases to be valid.
        /// This value is calculated based on current UTC time measured locally and the value expiresIn received from the
        /// service.
        /// </summary>
        public DateTimeOffset ExpiresOn => _accessTokenCacheItem.ExpiresOn;

        /// <summary>
        /// Gets an identifier for the tenant the token was acquired from. This property will be null if tenant information is
        /// not returned by the service.
        /// </summary>
        public string TenantId => _accessTokenCacheItem.TenantId;

        /// <summary>
        /// Gets User object. Some elements in User might be null if not returned by the
        /// service. It can be passed back in some API overloads to identify which user should be used.
        /// </summary>
        public User User { get; internal set; }

        /// <summary>
        /// Gets the entire Id Token if returned by the service or null if no Id Token is returned.
        /// </summary>
        public string IdToken => _accessTokenCacheItem.RawIdToken;

        /// <summary>
        /// Gets the scope values returned from the service.
        /// </summary>
        public string[] Scope => _accessTokenCacheItem.Scope.AsArray();

        /// <summary>
        /// Creates authorization header from authentication result.
        /// </summary>
        /// <returns>Created authorization header</returns>
        public string CreateAuthorizationHeader()
        {
            return Oauth2AuthorizationHeader + AccessToken;
        }
    }
}