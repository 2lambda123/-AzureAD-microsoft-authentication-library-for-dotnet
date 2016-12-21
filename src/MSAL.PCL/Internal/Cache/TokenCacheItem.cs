﻿//------------------------------------------------------------------------------
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
using System.Collections.Generic;
using System.Runtime.Serialization;
using Microsoft.Identity.Client.Internal.OAuth2;

namespace Microsoft.Identity.Client.Internal.Cache
{
    [DataContract]
    internal class TokenCacheItem : BaseTokenCacheItem
    {
        /// <summary>
        /// Gets the Token Type.
        /// </summary>
        [DataMember(Name = "token_type")]
        public string TokenType { get; internal set; }

        /// <summary>
        /// Gets the Access Token requested.
        /// </summary>
        [DataMember(Name = "token")]
        public string Token { get; internal set; }

        [DataMember(Name = "expires_on")]
        public DateTimeOffset ExpiresOn { get; internal set; }

        /// <summary>
        /// Gets the Scope.
        /// </summary>
        [DataMember(Name = "scope")]
        public SortedSet<string> Scope { get; internal set; }

        internal TokenCacheItem()
        {
        }

        public TokenCacheItem(string authority, string clientId, string policy, TokenResponse response)
            : base(authority, clientId, policy, response)
        {
            if (response.AccessToken != null)
            {
                Token = response.AccessToken;
                ExpiresOn = response.AccessTokenExpiresOn;
            }
            else if (response.IdToken != null)
            {
                Token = response.IdToken;
                ExpiresOn = response.IdTokenExpiresOn;
            }

            Scope = response.Scope.AsSet();
        }

        public override TokenCacheKey GetTokenCacheKey()
        {
            return new TokenCacheKey(Authority, Scope, ClientId, User, Policy);
        }
    }
}
