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
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Handlers;
using Microsoft.Identity.Client.Internal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Test.MSAL.Common.Unit;
using Test.MSAL.NET.Unit.Mocks;

namespace Test.MSAL.NET.Unit.HandlersTests
{
    [TestClass]
    public class AcquireTokenSilentHandlerTests
    {
        [TestMethod]
        [TestCategory("AcquireTokenSilentHandlerTests")]
        public void ConstructorTests()
        {
            Authenticator authenticator = new Authenticator(TestConstants.DefaultAuthorityHomeTenant, false,
                Guid.NewGuid());
            TokenCache cache = new TokenCache();
            HandlerData data = new HandlerData()
            {
                Authenticator = authenticator,
                ClientKey = new ClientKey(TestConstants.DefaultClientId),
                Policy = TestConstants.DefaultPolicy,
                RestrictToSingleUser = true,
                Scope = TestConstants.DefaultScope.ToArray(),
                TokenCache = cache
            };

            AcquireTokenSilentHandler handler = new AcquireTokenSilentHandler(data, (string) null,
                new PlatformParameters(), false);
            Assert.IsNotNull(handler);

            handler = new AcquireTokenSilentHandler(data, (User) null, new PlatformParameters(), false);
            Assert.IsNotNull(handler);

            handler = new AcquireTokenSilentHandler(data, TestConstants.DefaultDisplayableId, new PlatformParameters(), false);
            Assert.IsNotNull(handler);

            handler = new AcquireTokenSilentHandler(data, TestConstants.DefaultUniqueId, new PlatformParameters(), false);
            Assert.IsNotNull(handler);

            handler = new AcquireTokenSilentHandler(data, TestConstants.DefaultUser, new PlatformParameters(), false);
            Assert.IsNotNull(handler);
        }


        [TestMethod]
        [TestCategory("AcquireTokenSilentHandlerTests")]
        public void MapToIdentifierNullInputTest()
        {
            Authenticator authenticator = new Authenticator(TestConstants.DefaultAuthorityHomeTenant, false,
                Guid.NewGuid());
            TokenCache cache = new TokenCache();
            HandlerData data = new HandlerData()
            {
                Authenticator = authenticator,
                ClientKey = new ClientKey(TestConstants.DefaultClientId),
                Policy = TestConstants.DefaultPolicy,
                RestrictToSingleUser = true,
                Scope = TestConstants.DefaultScope.ToArray(),
                TokenCache = cache
            };

            AcquireTokenSilentHandler handler = new AcquireTokenSilentHandler(data, (string)null,
                new PlatformParameters(), false);
            User user = handler.MapIdentifierToUser(null);
            Assert.IsNull(user);
        }

        [TestMethod]
        [TestCategory("AcquireTokenSilentHandlerTests")]
        public void MapToIdentifierNoItemFoundTest()
        {
            Authenticator authenticator = new Authenticator(TestConstants.DefaultAuthorityHomeTenant, false,
                Guid.NewGuid());
            TokenCache cache = new TokenCache();
            HandlerData data = new HandlerData()
            {
                Authenticator = authenticator,
                ClientKey = new ClientKey(TestConstants.DefaultClientId),
                Policy = TestConstants.DefaultPolicy,
                RestrictToSingleUser = true,
                Scope = TestConstants.DefaultScope.ToArray(),
                TokenCache = cache
            };

            AcquireTokenSilentHandler handler = new AcquireTokenSilentHandler(data, (string) null,
                new PlatformParameters(), false);
            User user = handler.MapIdentifierToUser(TestConstants.DefaultUniqueId);
            Assert.IsNull(user);
        }

        [TestMethod]
        [TestCategory("AcquireTokenSilentHandlerTests")]
        public void MapToIdentifierItemFoundTest()
        {
            Authenticator authenticator = new Authenticator(TestConstants.DefaultAuthorityHomeTenant, false,
                Guid.NewGuid());
            TokenCache cache = TokenCacheHelper.CreateCacheWithItems();
            HandlerData data = new HandlerData()
            {
                Authenticator = authenticator,
                ClientKey = new ClientKey(TestConstants.DefaultClientId),
                Policy = TestConstants.DefaultPolicy,
                RestrictToSingleUser = TestConstants.DefaultRestrictToSingleUser,
                Scope = TestConstants.DefaultScope.ToArray(),
                TokenCache = cache
            };

            AcquireTokenSilentHandler handler = new AcquireTokenSilentHandler(data, (string)null,
                new PlatformParameters(), false);
            User user = handler.MapIdentifierToUser(TestConstants.DefaultUniqueId);
            Assert.IsNotNull(user);
            Assert.AreEqual(TestConstants.DefaultUniqueId, user.UniqueId);
        }

        [TestMethod]
        [TestCategory("AcquireTokenSilentHandlerTests")]
        public void MapToIdentifierMultipleMatchingEntriesTest()
        {
            Authenticator authenticator = new Authenticator(TestConstants.DefaultAuthorityHomeTenant, false,
                Guid.NewGuid());
            TokenCache cache = TokenCacheHelper.CreateCacheWithItems();

            TokenCacheKey key = new TokenCacheKey(TestConstants.DefaultAuthorityHomeTenant,
                TestConstants.ScopeForAnotherResource, TestConstants.DefaultClientId,
                TestConstants.DefaultUniqueId, TestConstants.DefaultDisplayableId, TestConstants.DefaultHomeObjectId,
                TestConstants.DefaultPolicy);
            AuthenticationResultEx ex = new AuthenticationResultEx();
            ex.Result = new AuthenticationResult("Bearer", key.ToString(),
                new DateTimeOffset(DateTime.UtcNow + TimeSpan.FromSeconds(3600)));
            ex.Result.User = new User
            {
                DisplayableId = TestConstants.DefaultDisplayableId,
                UniqueId = TestConstants.DefaultUniqueId,
                HomeObjectId = TestConstants.DefaultHomeObjectId
            };
            ex.Result.ScopeSet = TestConstants.DefaultScope;

            ex.Result.FamilyId = "1";
            ex.RefreshToken = "someRT";
            cache.tokenCacheDictionary[key] = ex;


            HandlerData data = new HandlerData()
            {
                Authenticator = authenticator,
                ClientKey = new ClientKey(TestConstants.DefaultClientId),
                Policy = TestConstants.DefaultPolicy,
                RestrictToSingleUser = TestConstants.DefaultRestrictToSingleUser,
                Scope = new[] { "something" },
                TokenCache = cache
            };

            AcquireTokenSilentHandler handler = new AcquireTokenSilentHandler(data, (string) null,
                new PlatformParameters(), false);
            User user = handler.MapIdentifierToUser(TestConstants.DefaultUniqueId);
            Assert.IsNotNull(user);
            Assert.AreEqual(TestConstants.DefaultUniqueId, user.UniqueId);
        }

        [TestMethod]
        [TestCategory("AcquireTokenSilentHandlerTests")]
        public void ExpiredTokenRefreshFlowTest()
        {
            Authenticator authenticator = new Authenticator(TestConstants.DefaultAuthorityHomeTenant, false,
                Guid.NewGuid());
            TokenCache cache = TokenCacheHelper.CreateCacheWithItems();

            HandlerData data = new HandlerData()
            {
                Authenticator = authenticator,
                ClientKey = new ClientKey(TestConstants.DefaultClientId),
                Policy = TestConstants.DefaultPolicy,
                RestrictToSingleUser = TestConstants.DefaultRestrictToSingleUser,
                Scope = new[] { "some-scope1", "some-scope2" },
                TokenCache = cache
            };

            HttpMessageHandlerFactory.MockHandler = new MockHttpMessageHandler()
            {
                Method = HttpMethod.Post,
                ResponseMessage = MockHelpers.CreateSuccessTokenResponseMessage()
            };

            AcquireTokenSilentHandler handler = new AcquireTokenSilentHandler(data, (string)null,
                new PlatformParameters(), false);
            Task<AuthenticationResult> task = handler.RunAsync();
            AuthenticationResult result = task.Result;
            Assert.IsNotNull(result);
            Assert.AreEqual("some-access-token", result.Token);
            Assert.AreEqual("some-scope1 some-scope2", result.Scope.AsSingleString());
        }


        [TestMethod]
        [TestCategory("AcquireTokenSilentHandlerTests")]
        public void SilentRefreshFailedNoCacheItemFoundTest()
        {
            Authenticator authenticator = new Authenticator(TestConstants.DefaultAuthorityHomeTenant, false,
                Guid.NewGuid());
            TokenCache cache = new TokenCache();

            HandlerData data = new HandlerData()
            {
                Authenticator = authenticator,
                ClientKey = new ClientKey(TestConstants.DefaultClientId),
                Policy = TestConstants.DefaultPolicy,
                RestrictToSingleUser = TestConstants.DefaultRestrictToSingleUser,
                Scope = new[] { "some-scope1", "some-scope2" },
                TokenCache = cache
            };

            HttpMessageHandlerFactory.MockHandler = new MockHttpMessageHandler()
            {
                Method = HttpMethod.Post,
                ResponseMessage = MockHelpers.CreateSuccessTokenResponseMessage()
            };

            try
            {
                AcquireTokenSilentHandler handler = new AcquireTokenSilentHandler(data, (string) null,
                    new PlatformParameters(), false);
                Task<AuthenticationResult> task = handler.RunAsync();
                var authenticationResult = task.Result;
                Assert.Fail("MsalSilentTokenAcquisitionException should be thrown here");
            }
            catch (AggregateException ae)
            {
                Assert.IsTrue(ae.InnerException is MsalSilentTokenAcquisitionException);
            }
        }
    }
}
