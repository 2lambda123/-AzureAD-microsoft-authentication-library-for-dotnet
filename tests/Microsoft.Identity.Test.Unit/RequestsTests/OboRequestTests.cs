﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Cache.Items;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Test.Common;
using Microsoft.Identity.Test.Common.Core.Helpers;
using Microsoft.Identity.Test.Common.Core.Mocks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Unit.RequestsTests
{
    [TestClass]
    public class OboRequestTests
    {
        [TestInitialize]
        public void TestInitialize()
        {
            TestCommon.ResetInternalStaticCaches();
        }

        private MockHttpMessageHandler AddMockHandlerAadSuccess(
            MockHttpManager httpManager,
            string authority = TestConstants.AuthorityCommonTenant,
            IList<string> unexpectedHeaders = null,
            HttpResponseMessage responseMessage = null)
        {
            var handler = new MockHttpMessageHandler
            {
                ExpectedUrl = authority + "oauth2/v2.0/token",
                ExpectedMethod = HttpMethod.Post,
                ResponseMessage = responseMessage ?? MockHelpers.CreateSuccessTokenResponseMessage(),
                UnexpectedRequestHeaders = unexpectedHeaders
            };
            httpManager.AddMockHandler(handler);

            return handler;
        }

        [TestMethod]
        public async Task AcquireTokenByObo_AccessTokenExpiredRefreshTokenNotAvailable_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                AddMockHandlerAadSuccess(httpManager);

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                UserAssertion userAssertion = new UserAssertion(TestConstants.DefaultAccessToken);
                var result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);

                //Expire access tokens
                TokenCacheHelper.ExpireAllAccessTokens(cca.UserTokenCacheInternal);

                MockHttpMessageHandler mockTokenRequestHttpHandlerRefresh = AddMockHandlerAadSuccess(httpManager);
                mockTokenRequestHttpHandlerRefresh.ExpectedPostData = new Dictionary<string, string> { { OAuth2Parameter.GrantType, OAuth2GrantType.JwtBearer } };

                result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
            }
        }

        [TestMethod]
        public async Task AcquireTokenByObo_MissMatchUserAssertions_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                AddMockHandlerAadSuccess(httpManager);

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                UserAssertion userAssertion = new UserAssertion(TestConstants.DefaultAccessToken);
                var result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);

                //Update user assertions
                TokenCacheHelper.UpdateUserAssertions(cca);

                MockHttpMessageHandler mockTokenRequestHttpHandlerRefresh = AddMockHandlerAadSuccess(httpManager);

                //Access and refresh tokens have a different user assertion so MSAL should perform OBO.
                result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(result.AuthenticationResultMetadata.TokenSource, TokenSource.IdentityProvider);
            }
        }

        [TestMethod]
        public async Task AcquireTokenByObo_AccessTokenInCache_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                AddMockHandlerAadSuccess(httpManager);

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                var userCacheAccess = cca.UserTokenCache.RecordAccess();

                UserAssertion userAssertion = new UserAssertion(TestConstants.DefaultAccessToken);
                var result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
                userCacheAccess.AssertAccessCounts(1, 1);

                result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                userCacheAccess.AssertAccessCounts(2, 1);

                MsalAccessTokenCacheItem cachedAccessToken = cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().Single();
                Assert.AreEqual(userAssertion.AssertionHash, cachedAccessToken.OboCacheKey);
                Assert.AreEqual(0, cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().Count);
            }
        }

        [TestMethod]
        public async Task AcquireTokenByObo_InLongRunningProcess_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                AddMockHandlerAadSuccess(httpManager);

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                var userCacheAccess = cca.UserTokenCache.RecordAccess();

                string oboCacheKey = "obo-cache-key";
                var result = await cca.InitiateLongRunningProcessInWebApi(TestConstants.s_scope, TestConstants.DefaultAccessToken, ref oboCacheKey)
                    .ExecuteAsync().ConfigureAwait(false);

                // Token's not in cache, searched by user assertion hash, retrieved from IdP, saved with the provided OBO cache key
                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
                MsalAccessTokenCacheItem cachedAccessToken = cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().Single();
                MsalRefreshTokenCacheItem cachedRefreshToken = cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().Single();
                Assert.AreEqual(oboCacheKey, cachedAccessToken.OboCacheKey);
                Assert.AreEqual(oboCacheKey, cachedRefreshToken.OboCacheKey);
                userCacheAccess.AssertAccessCounts(1, 1);

                result = await cca.AcquireTokenInLongRunningProcess(TestConstants.s_scope, oboCacheKey).ExecuteAsync().ConfigureAwait(false);

                // Token is in the cache, retrieved by the provided OBO cache key
                Assert.IsNotNull(result);
                Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                userCacheAccess.AssertAccessCounts(2, 1);

                TokenCacheHelper.ExpireAllAccessTokens(cca.UserTokenCacheInternal);
                AddMockHandlerAadSuccess(httpManager,
                    responseMessage: MockHelpers.CreateSuccessTokenResponseMessage(
                        TestConstants.UniqueId,
                        TestConstants.DisplayableId,
                        TestConstants.s_scope.ToArray(),
                        utid: TestConstants.Utid2,
                        accessToken: TestConstants.ATSecret2,
                        refreshToken: TestConstants.RTSecret2));

                result = await cca.AcquireTokenInLongRunningProcess(TestConstants.s_scope, oboCacheKey).ExecuteAsync().ConfigureAwait(false);

                // Cached AT is expired, RT used to retrieve new AT
                Assert.IsNotNull(result);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
                Assert.AreEqual(TestConstants.ATSecret2, result.AccessToken);
                userCacheAccess.AssertAccessCounts(3, 2);
            }
        }

        [TestMethod]
        public async Task AcquireTokenByObo_InitiateLongRunningProcessInWebApi_CacheKeyAlreadyExists_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                var userCacheAccess = cca.UserTokenCache.RecordAccess();

                AddMockHandlerAadSuccess(httpManager,
                    responseMessage: MockHelpers.CreateSuccessTokenResponseMessage(
                        TestConstants.UniqueId,
                        TestConstants.DisplayableId,
                        TestConstants.s_scope.ToArray(),
                        accessToken: TestConstants.ATSecret,
                        refreshToken: TestConstants.RTSecret));

                string oboCacheKey = "obo-cache-key";
                var result = await cca.InitiateLongRunningProcessInWebApi(TestConstants.s_scope, TestConstants.DefaultAccessToken, ref oboCacheKey)
                    .ExecuteAsync().ConfigureAwait(false);

                // Cache is empty or token with the same scopes, OBO cache key, etc. not in cache -> AT and RT are retrieved from IdP and saved
                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
                MsalAccessTokenCacheItem cachedAccessToken = cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().Single();
                MsalRefreshTokenCacheItem cachedRefreshToken = cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().Single();
                Assert.AreEqual(oboCacheKey, cachedAccessToken.OboCacheKey);
                Assert.AreEqual(oboCacheKey, cachedRefreshToken.OboCacheKey);
                Assert.AreEqual(TestConstants.RTSecret, cachedRefreshToken.Secret);
                userCacheAccess.AssertAccessCounts(1, 1);

                // Token with the same scopes, OBO cache key, etc. exists in the cache -> AT is retrieved from the cache
                result = await cca.InitiateLongRunningProcessInWebApi(TestConstants.s_scope, TestConstants.DefaultAccessToken, ref oboCacheKey)
                    .ExecuteAsync().ConfigureAwait(false);
                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
                Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);
                cachedAccessToken = cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().Single();
                cachedRefreshToken = cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().Single();
                Assert.AreEqual(oboCacheKey, cachedAccessToken.OboCacheKey);
                Assert.AreEqual(oboCacheKey, cachedRefreshToken.OboCacheKey);
                Assert.AreEqual(TestConstants.RTSecret, cachedRefreshToken.Secret);
                userCacheAccess.AssertAccessCounts(2, 1);

                AddMockHandlerAadSuccess(httpManager,
                    responseMessage: MockHelpers.CreateSuccessTokenResponseMessage(
                        $"{TestConstants.UniqueId}2",
                        $"{TestConstants.DisplayableId}2",
                        new string[] { "differentscope" },
                        utid: TestConstants.Utid2,
                        accessToken: TestConstants.ATSecret2,
                        refreshToken: TestConstants.RTSecret2));

                // Token with the same OBO cache key but different scopes, etc. exists in the cache -> save AT and RT in the cache since it's a different token
                // This mirrors the current behavior with AcquireTokenOnBehalfOf - two different tokens with the same user assertion can exist in the cache
                result = await cca.InitiateLongRunningProcessInWebApi(new string[] { "differentscope" }, $"{TestConstants.DefaultAccessToken}2", ref oboCacheKey)
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret2, result.AccessToken);
                Assert.AreEqual(result.AuthenticationResultMetadata.TokenSource, TokenSource.IdentityProvider);
                cachedAccessToken = cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().FirstOrDefault(at => at.Secret.Equals(TestConstants.ATSecret2));
                cachedRefreshToken = cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().FirstOrDefault(rt => rt.Secret.Equals(TestConstants.RTSecret2));
                Assert.AreEqual(oboCacheKey, cachedAccessToken.OboCacheKey);
                Assert.AreEqual(oboCacheKey, cachedRefreshToken.OboCacheKey);
                Assert.AreEqual(TestConstants.RTSecret2, cachedRefreshToken.Secret);
                userCacheAccess.AssertAccessCounts(3, 2);
            }
        }

        [TestMethod]
        public async Task AcquireTokenByObo_AcquireTokenInLongRunningProcess_CacheKeyDoesNotExist_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                var userCacheAccess = cca.UserTokenCache.RecordAccess();

                string oboCacheKey = "obo-cache-key";

                // If token with OBO cache key provided does not exist in the cache throw error
                var exception = await AssertException.TaskThrowsAsync<MsalClientException>(
                    () => cca.AcquireTokenInLongRunningProcess(TestConstants.s_scope.ToArray(), oboCacheKey)
                    .ExecuteAsync())
                    .ConfigureAwait(false);

                Assert.AreEqual(MsalError.OboCacheKeyNotInCacheError, exception.ErrorCode);
                userCacheAccess.AssertAccessCounts(1, 0);
            }
        }

        [TestMethod]
        public async Task AcquireTokenByObo_InLongRunningProcess_WithNullCacheKey_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                AddMockHandlerAadSuccess(httpManager);

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                string cacheKey = null;
                await cca.InitiateLongRunningProcessInWebApi(TestConstants.s_scope, TestConstants.DefaultAccessToken, ref cacheKey)
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                // If not provided, cache key is defaulted to the assertion hash.
                Assert.AreEqual(new UserAssertion(TestConstants.DefaultAccessToken).AssertionHash, cacheKey);

                // Cache key is required in this method
                await AssertException.TaskThrowsAsync<ArgumentNullException>(
                    () => cca.AcquireTokenInLongRunningProcess(TestConstants.s_scope, null)
                        .ExecuteAsync())
                    .ConfigureAwait(false);
            }
        }

        [TestMethod]
        public async Task AcquireTokenByObo_NullCcs_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();
                var extraUnexpectedHeaders = new List<string>() { { Constants.CcsRoutingHintHeader } };
                AddMockHandlerAadSuccess(httpManager, unexpectedHeaders: extraUnexpectedHeaders);

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                UserAssertion userAssertion = new UserAssertion(TestConstants.DefaultAccessToken);
                var result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion)
                                      .WithCcsRoutingHint("")
                                      .WithCcsRoutingHint("", "")
                                      .ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);

                result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion)
                      .WithCcsRoutingHint("")
                      .WithCcsRoutingHint("", "")
                      .ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);
                Assert.AreEqual(TestConstants.ATSecret, result.AccessToken);
            }
        }

        /// <summary>
        /// Tests the behavior when calling both, long-running and normal OBO methods.
        /// Long-running OBO method return cached long-running tokens.
        /// Normal OBO method return cached normal tokens.
        /// Should be different partitions: by user-provided and by assertion hash.
        /// </summary>
        [TestMethod]
        public async Task AcquireTokenByObo_LongRunningAndNormalObo_TestAsync()
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();

                var cca = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                AddMockHandlerAadSuccess(httpManager,
                    responseMessage: MockHelpers.CreateSuccessTokenResponseMessage(
                        TestConstants.Uid,
                        TestConstants.DisplayableId,
                        TestConstants.s_scope.ToArray(),
                        utid: TestConstants.Utid,
                        accessToken: "access-token-long-running",
                        refreshToken: "refresh-token-long-running"));

                string oboCacheKey = "obo-cache-key";
                string longRunningUserToken = "long-running-assertion";
                var result = await cca.InitiateLongRunningProcessInWebApi(TestConstants.s_scope, longRunningUserToken, ref oboCacheKey)
                    .ExecuteAsync().ConfigureAwait(false);

                // Cache has 1 partition (user-provided key) with 1 token
                Assert.IsNotNull(result);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
                Assert.AreEqual(1, cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().Count);
                Assert.AreEqual(1, cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().Count);
                MsalAccessTokenCacheItem cachedAccessToken = cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().First(t => t.OboCacheKey.Equals(oboCacheKey));
                MsalRefreshTokenCacheItem cachedRefreshToken = cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().First(t => t.OboCacheKey.Equals(oboCacheKey));
                Assert.AreEqual("access-token-long-running", result.AccessToken);
                Assert.AreEqual("access-token-long-running", cachedAccessToken.Secret);
                Assert.AreEqual("refresh-token-long-running", cachedRefreshToken.Secret);

                AddMockHandlerAadSuccess(httpManager,
                    responseMessage: MockHelpers.CreateSuccessTokenResponseMessage(
                        TestConstants.Uid,
                        TestConstants.DisplayableId,
                        TestConstants.s_scope.ToArray(),
                        utid: TestConstants.Utid,
                        accessToken: "access-token-normal",
                        refreshToken: "refresh-token-normal"));

                UserAssertion userAssertion = new UserAssertion(TestConstants.DefaultAccessToken);
                result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);

                // Cache has 2 partitions (user-provided key, assertion) with 1 token each
                Assert.IsNotNull(result);
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
                Assert.AreEqual(2, cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().Count);
                Assert.AreEqual(1, cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().Count);
                cachedAccessToken = cca.UserTokenCacheInternal.Accessor.GetAllAccessTokens().First(t => t.OboCacheKey.Equals(userAssertion.AssertionHash));
                cachedRefreshToken = cca.UserTokenCacheInternal.Accessor.GetAllRefreshTokens().FirstOrDefault(t => t.OboCacheKey.Equals(userAssertion.AssertionHash));
                Assert.AreEqual("access-token-normal", result.AccessToken);
                Assert.AreEqual("access-token-normal", cachedAccessToken.Secret);
                Assert.IsNull(cachedRefreshToken);

                // Returns long-running token
                result = await cca.AcquireTokenInLongRunningProcess(TestConstants.s_scope, oboCacheKey).ExecuteAsync().ConfigureAwait(false);
                Assert.IsNotNull(result);
                Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);
                Assert.AreEqual("access-token-long-running", result.AccessToken);

                // Returns normal token
                result = await cca.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);
                Assert.IsNotNull(result);
                Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);
                Assert.AreEqual("access-token-normal", result.AccessToken);
            }
        }

        [DataTestMethod]
        [DataRow(true)]
        [DataRow(false)]
        public async Task AcquireTokenByObo_SuggestedCacheExpiry_TestAsync(bool shouldHaveSuggestedCacheExpiry)
        {
            using (var httpManager = new MockHttpManager())
            {
                httpManager.AddInstanceDiscoveryMockHandler();
                AddMockHandlerAadSuccess(httpManager);

                var app = ConfidentialClientApplicationBuilder
                                                         .Create(TestConstants.ClientId)
                                                         .WithClientSecret(TestConstants.ClientSecret)
                                                         .WithAuthority(TestConstants.AuthorityCommonTenant)
                                                         .WithHttpManager(httpManager)
                                                         .BuildConcrete();

                InMemoryTokenCache cache = new InMemoryTokenCache();
                cache.Bind(app.UserTokenCache);

                (app.UserTokenCache as TokenCache).AfterAccess += (args) =>
                {
                    if (args.HasStateChanged == true)
                    {
                        Assert.AreEqual(shouldHaveSuggestedCacheExpiry, args.SuggestedCacheExpiry.HasValue);
                    }
                };

                if (shouldHaveSuggestedCacheExpiry)
                {
                    UserAssertion userAssertion = new UserAssertion(TestConstants.DefaultAccessToken);
                    await app.AcquireTokenOnBehalfOf(TestConstants.s_scope, userAssertion).ExecuteAsync().ConfigureAwait(false);
                }
                else
                {
                    string oboCacheKey = "obo-cache-key";
                    await app.InitiateLongRunningProcessInWebApi(TestConstants.s_scope, TestConstants.DefaultAccessToken, ref oboCacheKey)
                        .ExecuteAsync().ConfigureAwait(false);
                }
            }
        }
    }
}
