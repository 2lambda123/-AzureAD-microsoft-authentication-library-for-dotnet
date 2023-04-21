﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;
using Microsoft.Identity.Client.AuthScheme;
using Microsoft.Identity.Client.Cache;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Client.ManagedIdentity;
using Microsoft.Identity.Client.TelemetryCore;
using Microsoft.Identity.Client.TelemetryCore.TelemetryClient;
using Microsoft.Identity.Client.Utils;
using Microsoft.Identity.Test.Common.Core.Helpers;
using Microsoft.Identity.Test.Common.Core.Mocks;
using Microsoft.Identity.Test.Common.Mocks;
using Microsoft.Identity.Test.Unit.TelemetryTests;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using static Microsoft.Identity.Test.Common.Core.Helpers.ManagedIdentityTestUtil;

namespace Microsoft.Identity.Test.Unit.PublicApiTests
{
    [TestClass]
    public class TelemetryClientTests : TestBase
    {
        private MockHttpAndServiceBundle _harness;
        private ConfidentialClientApplication _cca;
        private TestTelemetryClient _telemetryClient;

        [TestInitialize]
        public override void TestInitialize()
        {
            _telemetryClient = new TestTelemetryClient(TestConstants.ClientId);
            base.TestInitialize();
        }

        [TestCleanup] 
        public override void TestCleanup()
        {
            base.TestCleanup();
        }

        [TestMethod]
        public void TelemetryClientExperimental()
        {
            var e = AssertException.Throws<MsalClientException>(() => ConfidentialClientApplicationBuilder
                .Create(TestConstants.ClientId)
                .WithClientSecret("secret")
                .WithTelemetryClient(_telemetryClient)
                .Build());

            Assert.AreEqual(MsalError.ExperimentalFeature, e.ErrorCode);
        }

        [TestMethod]
        public void TelemetryClientListNull()
        {
            var e = AssertException.Throws<ArgumentNullException>(() => ConfidentialClientApplicationBuilder
                .Create(TestConstants.ClientId)
                .WithExperimentalFeatures()
                .WithClientSecret("secret")
                .WithTelemetryClient(null)
                .Build());

            Assert.AreEqual("telemetryClients", e.ParamName);
        }

        [TestMethod]
        public void TelemetryClientNullClientInList()
        {
            var e = AssertException.Throws<ArgumentNullException>(() => ConfidentialClientApplicationBuilder
                .Create(TestConstants.ClientId)
                .WithExperimentalFeatures()
                .WithClientSecret("secret")
                .WithTelemetryClient(_telemetryClient, null)
                .Build());

            Assert.AreEqual("telemetryClient", e.ParamName);
        }

        [TestMethod]
        public void TelemetryClientNoArg()
        {
            var cca = ConfidentialClientApplicationBuilder
                .Create(TestConstants.ClientId)
                .WithExperimentalFeatures()
                .WithClientSecret("secret")
                .WithTelemetryClient()
                .Build();

            Assert.IsNotNull(cca);
        }

        [TestMethod] 
        public async Task AcquireTokenSuccessfulTelemetryTestAsync()
        {
            using (_harness = CreateTestHarness())
            {
                _harness.HttpManager.AddInstanceDiscoveryMockHandler();
                
                CreateApplication();
                _harness.HttpManager.AddMockHandlerSuccessfulClientCredentialTokenResponseMessage();

                // Acquire token interactively with scope
                var result = await _cca.AcquireTokenForClient(TestConstants.s_scope)
                    .WithAuthority(TestConstants.AuthorityUtidTenant)
                    .ExecuteAsync(CancellationToken.None).ConfigureAwait(false);

                Assert.IsNotNull(result);

                MsalTelemetryEventDetails eventDetails = _telemetryClient.TestTelemetryEventDetails;
                AssertLoggedTelemetry(
                    result, 
                    eventDetails, 
                    TokenSource.IdentityProvider, 
                    CacheRefreshReason.NoCachedAccessToken, 
                    AssertionType.Secret,
                    TestConstants.AuthorityUtidTenant,
                    TokenType.Bearer,
                    CacheTypeUsed.None,
                    JsonHelper.SerializeToJson(TestConstants.s_scope));

                // Acquire token silently
                var account = (await _cca.GetAccountsAsync().ConfigureAwait(false)).Single();
                result = await _cca.AcquireTokenSilent(TestConstants.s_scope, account)
                    .WithAuthority(TestConstants.AuthorityUtidTenant)
                    .ExecuteAsync().ConfigureAwait(false);
                Assert.IsNotNull(result);

                eventDetails = _telemetryClient.TestTelemetryEventDetails;
                AssertLoggedTelemetry(
                    result, 
                    eventDetails, 
                    TokenSource.Cache, 
                    CacheRefreshReason.NotApplicable,
                    AssertionType.Secret,
                    TestConstants.AuthorityUtidTenant);

                _harness.HttpManager.AddMockHandlerSuccessfulClientCredentialTokenResponseMessage();

                // Acquire token interactively with resource
                result = await _cca.AcquireTokenForClient(new[] { TestConstants.DefaultGraphScope })
                    .WithAuthority(TestConstants.AuthorityUtidTenant)
                    .ExecuteAsync(CancellationToken.None).ConfigureAwait(false);

                Assert.IsNotNull(result);

                eventDetails = _telemetryClient.TestTelemetryEventDetails;
                AssertLoggedTelemetry(
                    result,
                    eventDetails,
                    TokenSource.IdentityProvider,
                    CacheRefreshReason.NoCachedAccessToken,
                    AssertionType.Secret,
                    TestConstants.AuthorityUtidTenant,
                    TokenType.Bearer,
                    CacheTypeUsed.None,
                    null,
                    TestConstants.DefaultGraphScope);
            }
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public async Task AcquireTokenAssertionTypeTelemetryTestAsync(int assertionType)
        {
            using (_harness = CreateTestHarness())
            {
                _harness.HttpManager.AddInstanceDiscoveryMockHandler();

                CreateApplication((AssertionType)assertionType);
                if (assertionType != 5)
                {
                    _harness.HttpManager.AddMockHandlerSuccessfulClientCredentialTokenResponseMessage();
                }

                var result = await _cca.AcquireTokenForClient(TestConstants.s_scope)
                    .WithAuthority(TestConstants.AuthorityUtidTenant)
                    .ExecuteAsync(CancellationToken.None).ConfigureAwait(false);

                Assert.IsNotNull(result);

                MsalTelemetryEventDetails eventDetails = _telemetryClient.TestTelemetryEventDetails;
                AssertLoggedTelemetry(
                    result,
                    eventDetails,
                    TokenSource.IdentityProvider,
                    CacheRefreshReason.NoCachedAccessToken,
                    (AssertionType)assertionType,
                    TestConstants.AuthorityUtidTenant);
            }
        }

        [TestMethod]
        public async Task AcquireTokenCacheTelemetryTestAsync()
        {
            using (_harness = CreateTestHarness())
            {
                //Create app
                CacheTypeUsed cacheTypeUsed = CacheTypeUsed.L1Cache;
                _harness.HttpManager.AddInstanceDiscoveryMockHandler();
                CreateApplication();

                _harness.HttpManager.AddMockHandlerSuccessfulClientCredentialTokenResponseMessage();

                //Configure cache
                _cca.AppTokenCache.SetBeforeAccess((args) =>
                {
                    args.TelemetryDatapoints.CacheTypeUsed = cacheTypeUsed;
                });

                _cca.AppTokenCache.SetAfterAccess((args) =>
                {
                    args.TelemetryDatapoints.CacheTypeUsed = cacheTypeUsed;
                });

                //Acquire Token
                var result = await _cca.AcquireTokenForClient(TestConstants.s_scope)
                    .WithAuthority(TestConstants.AuthorityUtidTenant)
                    .ExecuteAsync(CancellationToken.None).ConfigureAwait(false);

                Assert.IsNotNull(result);

                MsalTelemetryEventDetails eventDetails = _telemetryClient.TestTelemetryEventDetails;

                //Validate telemetry
                AssertLoggedTelemetry(
                    result,
                    eventDetails,
                    TokenSource.IdentityProvider,
                    CacheRefreshReason.NoCachedAccessToken,
                    AssertionType.Secret,
                    TestConstants.AuthorityUtidTenant,
                    TokenType.Bearer,
                    cacheTypeUsed);

                //Update cache type
                cacheTypeUsed = CacheTypeUsed.L2Cache;

                //Acquire Token
                result = await _cca.AcquireTokenForClient(TestConstants.s_scope)
                    .WithAuthority(TestConstants.AuthorityUtidTenant)
                    .ExecuteAsync(CancellationToken.None).ConfigureAwait(false);

                Assert.IsNotNull(result);

                eventDetails = _telemetryClient.TestTelemetryEventDetails;

                //Validate telemetry
                AssertLoggedTelemetry(
                    result,
                    eventDetails,
                    TokenSource.Cache,
                    CacheRefreshReason.NotApplicable,
                    AssertionType.Secret,
                    TestConstants.AuthorityUtidTenant,
                    TokenType.Bearer,
                    cacheTypeUsed);
            }
        }

        [TestMethod]
        public async Task AcquireTokenWithMSITelemetryTestAsync()
        {
            using (new EnvVariableContext())
            using (_harness = CreateTestHarness())
            {
                string endpoint = "http://localhost:40342/metadata/identity/oauth2/token";
                string resource = "https://management.azure.com";

                Environment.SetEnvironmentVariable("MSI_ENDPOINT", endpoint);

                var mia = ManagedIdentityApplicationBuilder
                    .Create("clientId")
                    .WithHttpManager(_harness.HttpManager)
                    .WithTelemetryClient(_telemetryClient)
                    .Build();

                _harness.HttpManager.AddManagedIdentityMockHandler(
                    endpoint,
                    resource,
                    MockHelpers.GetMsiSuccessfulResponse(),
                    ManagedIdentitySource.CloudShell);

                var result = await mia.AcquireTokenForManagedIdentity(resource)
                    .ExecuteAsync().ConfigureAwait(false);

                Assert.IsNotNull(result);

                MsalTelemetryEventDetails eventDetails = _telemetryClient.TestTelemetryEventDetails;
                AssertLoggedTelemetry(
                    result,
                    eventDetails,
                    TokenSource.IdentityProvider,
                    CacheRefreshReason.NoCachedAccessToken,
                    AssertionType.Msi,
                    TestConstants.AuthorityCommonTenant);
            }
        }

        [TestMethod]
        public async Task AcquireTokenUnSuccessfulTelemetryTestAsync()
        {
            using (_harness = CreateTestHarness())
            {
                _harness.HttpManager.AddInstanceDiscoveryMockHandler();

                CreateApplication();
                _harness.HttpManager.AddTokenResponse(TokenResponseType.InvalidClient);

                MsalServiceException ex = await AssertException.TaskThrowsAsync<MsalServiceException>(
                    () => _cca.AcquireTokenForClient(TestConstants.s_scope)
                    .WithAuthority(TestConstants.AuthorityUtidTenant)
                    .ExecuteAsync(CancellationToken.None)).ConfigureAwait(false);

                Assert.IsNotNull(ex);
                Assert.IsNotNull(ex.ErrorCode);

                MsalTelemetryEventDetails eventDetails = _telemetryClient.TestTelemetryEventDetails;
                Assert.AreEqual(ex.ErrorCode, eventDetails.Properties[TelemetryConstants.ErrorCode]);
                Assert.IsFalse((bool?)eventDetails.Properties[TelemetryConstants.Succeeded]);
            }
        }

        private void AssertLoggedTelemetry(
                        AuthenticationResult authenticationResult, 
                        MsalTelemetryEventDetails eventDetails, 
                        TokenSource tokenSource, 
                        CacheRefreshReason cacheRefreshReason,
                        AssertionType assertionType,
                        string endpoint,
                        TokenType? tokenType = TokenType.Bearer,
                        CacheTypeUsed cacheTypeUsed = CacheTypeUsed.None,
                        string scopes = null,
                        string resource = null)
        {
            Assert.IsNotNull(eventDetails);
            Assert.AreEqual(Convert.ToInt64(cacheRefreshReason), eventDetails.Properties[TelemetryConstants.CacheInfoTelemetry]);
            Assert.AreEqual(Convert.ToInt64(tokenSource), eventDetails.Properties[TelemetryConstants.TokenSource]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationTotalInMs, eventDetails.Properties[TelemetryConstants.Duration]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationInHttpInMs, eventDetails.Properties[TelemetryConstants.DurationInHttp]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationInCacheInMs, eventDetails.Properties[TelemetryConstants.DurationInCache]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationTotalInMs, eventDetails.Properties[TelemetryConstants.Duration]);
            Assert.AreEqual(Convert.ToInt64(assertionType), eventDetails.Properties[TelemetryConstants.AssertionType]);
            Assert.AreEqual(Convert.ToInt64(tokenType), eventDetails.Properties[TelemetryConstants.TokenType]);
            Assert.AreEqual(endpoint, eventDetails.Properties[TelemetryConstants.Endpoint]);
            Assert.AreEqual(Convert.ToInt64(cacheTypeUsed), eventDetails.Properties[TelemetryConstants.CacheUsed]);

            if (!string.IsNullOrWhiteSpace(scopes))
            {
                Assert.AreEqual(scopes, eventDetails.Properties[TelemetryConstants.Scopes]);
            }

            if (!string.IsNullOrWhiteSpace(resource))
            {
                Assert.AreEqual(resource, eventDetails.Properties[TelemetryConstants.Resource]);
            }
        }

        private void CreateApplication(AssertionType assertionType = AssertionType.Secret)
        {
            var certificate = new X509Certificate2(
                                    ResourceHelper.GetTestResourceRelativePath("valid_cert.pfx"),
                                    TestConstants.DefaultPassword);
            switch (assertionType)
            {
                case AssertionType.Secret:
                    _cca = ConfidentialClientApplicationBuilder
                        .Create(TestConstants.ClientId)
                        .WithClientSecret(TestConstants.ClientSecret)
                        .WithHttpManager(_harness.HttpManager)
                        .WithExperimentalFeatures()
                        .WithTelemetryClient(_telemetryClient)
                        .BuildConcrete();
                        break;
                case AssertionType.CertificateWithoutSni:
                    _cca = ConfidentialClientApplicationBuilder
                        .Create(TestConstants.ClientId)
                        .WithCertificate(certificate)
                        .WithHttpManager(_harness.HttpManager)
                        .WithExperimentalFeatures()
                        .WithTelemetryClient(_telemetryClient)
                        .BuildConcrete();
                    break;
                case AssertionType.CertificateWithSni:
                    _cca = ConfidentialClientApplicationBuilder
                        .Create(TestConstants.ClientId)
                        .WithCertificate(certificate, true)
                        .WithHttpManager(_harness.HttpManager)
                        .WithExperimentalFeatures()
                        .WithTelemetryClient(_telemetryClient)
                        .BuildConcrete();
                    break;
                case AssertionType.ClientAssertion:
                    _cca = ConfidentialClientApplicationBuilder
                        .Create(TestConstants.ClientId)
                        .WithClientAssertion(TestConstants.DefaultClientAssertion)
                        .WithHttpManager(_harness.HttpManager)
                        .WithExperimentalFeatures()
                        .WithTelemetryClient(_telemetryClient)
                        .BuildConcrete();
                    break;
                case AssertionType.Msi:
                    _cca = ConfidentialClientApplicationBuilder
                        .Create(TestConstants.ClientId)
                        .WithAppTokenProvider((AppTokenProviderParameters parameters) => { return Task.FromResult(GetAppTokenProviderResult()); })
                        .WithHttpManager(_harness.HttpManager)
                        .WithExperimentalFeatures()
                        .WithTelemetryClient(_telemetryClient)
                        .BuildConcrete();
                    break;
            }


            TokenCacheHelper.PopulateCache(_cca.UserTokenCacheInternal.Accessor);
        }
    }
}
