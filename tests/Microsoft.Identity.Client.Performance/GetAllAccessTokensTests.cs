﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.Identity.Client;
using Microsoft.Identity.Test.Common.Core.Mocks;
using Microsoft.Identity.Test.Unit;

namespace Microsoft.Identity.Test.Performance
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("AsyncUsage.CSharp.Usage", "UseConfigureAwait:Use ConfigureAwait", Justification = "Test project, inapplicable.")]
    public class GetAllAccessTokensTests
    {
        private AcquireTokenForClientParameterBuilder _acquireTokenForClientBuilder;

        [Params(100, 1000, 10000, 100000)]
        public int TokenCacheSize { get; set; }

        [GlobalSetup]
        public void GlobalSetup()
        {
            var cca = ConfidentialClientApplicationBuilder
                .Create(TestConstants.ClientId)
                .WithAuthority(new Uri(TestConstants.AuthorityTestTenant))
                .WithRedirectUri(TestConstants.RedirectUri)
                .WithClientSecret(TestConstants.ClientSecret)
                .BuildConcrete();

            var inMemoryTokenCache = new InMemoryTokenCache();
            inMemoryTokenCache.Bind(cca.AppTokenCache);

            TokenCacheHelper tokenCacheHelper = new TokenCacheHelper();

            tokenCacheHelper.PopulateCacheForClientCredential(cca.AppTokenCacheInternal.Accessor, TokenCacheSize);

            _acquireTokenForClientBuilder = cca
                .AcquireTokenForClient(TestConstants.s_scope)
                .WithForceRefresh(false);
        }

        [Benchmark]
        public async Task<AuthenticationResult> AcquireTokenForClientTestAsync()
        {
            return await _acquireTokenForClientBuilder
                .ExecuteAsync(System.Threading.CancellationToken.None);
        }
    }
}
