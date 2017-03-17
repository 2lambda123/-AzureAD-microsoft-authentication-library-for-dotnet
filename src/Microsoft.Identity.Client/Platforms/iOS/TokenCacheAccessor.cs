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
using System.Collections.Generic;
using Foundation;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.Internal.Cache;
using Security;

namespace Microsoft.Identity.Client
{
    internal class TokenCacheAccessor : ITokenCAcheAccessor
    {

        private RequestContext _requestContext;

        public TokenCacheAccessor()
        {
        }

        public TokenCacheAccessor(RequestContext requestContext) : this()
        {
            _requestContext = requestContext;
        }

        public void SaveAccessToken(string cacheKey, string item)
        {
            throw new NotImplementedException();
        }

        public void SaveRefreshToken(string cacheKey, string item)
        {
            throw new NotImplementedException();
        }

        public string GetRefreshToken(string refreshTokenKey)
        {
            throw new NotImplementedException();
        }

        public void DeleteAccessToken(string cacheKey)
        {
            throw new NotImplementedException();
        }

        public void DeleteRefreshToken(string cacheKey)
        {
            throw new NotImplementedException();
        }

        public ICollection<string> GetAllAccessTokensAsString()
        {
            throw new NotImplementedException();
        }

        public ICollection<string> GetAllRefreshTokensAsString()
        {
            throw new NotImplementedException();
        }
    }
}
