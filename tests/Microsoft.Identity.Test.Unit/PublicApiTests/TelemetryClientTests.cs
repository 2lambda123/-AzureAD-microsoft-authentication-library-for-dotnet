﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.TelemetryCore;
using Microsoft.Identity.Test.Common.Core.Helpers;
using Microsoft.Identity.Test.Common.Core.Mocks;
using Microsoft.Identity.Test.Common.Mocks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Unit.PublicApiTests
{
    [TestClass]
    public class TelemetryClientTests : TestBase
    {
        private MockHttpAndServiceBundle _harness;
        private PublicClientApplication _pca;
        private ITelemetryClient _telemetryClient;

        [TestInitialize]
        public override void TestInitialize()
        {
            _telemetryClient = new TelemetryClient(TestConstants.ClientId);
            base.TestInitialize();
        }

        [TestCleanup] 
        public override void TestCleanup()
        {
            _harness?.Dispose();
            base.TestCleanup();
        }

        [TestMethod]
        public void TelemetryClientExperimental()
        {
            ITelemetryClient telemetryClient = new TelemetryClient(TestConstants.ClientId);

            var e = AssertException.Throws<MsalClientException>(() => ConfidentialClientApplicationBuilder
                .Create(TestConstants.ClientId)
                .WithClientSecret("secret")
                .WithTelemetryClient(telemetryClient)
                .Build());

            Assert.AreEqual(MsalError.ExperimentalFeature, e.ErrorCode);
        }

        [TestMethod] 
        public async Task AcquireTokenSuccessfulTelemetryTestAsync()
        {
            using (_harness = CreateTestHarness())
            {
                _harness.HttpManager.AddInstanceDiscoveryMockHandler();
                
                _pca = CreateApplication();
                _pca.ServiceBundle.ConfigureMockWebUI();
                _harness.HttpManager.AddSuccessTokenResponseMockHandlerForPost();

                // Acquire token interactively
                var result = await _pca
                    .AcquireTokenInteractive(TestConstants.s_scope)
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                Assert.IsNotNull(result);

                MsalTelemetryEventDetails eventDetails = ((TelemetryClient)_telemetryClient).TestTelemetryEventDetails;
                AssertLoggedTelemetry(result, eventDetails, TokenSource.IdentityProvider, CacheRefreshReason.NotApplicable);

                // Acquire token silently
                var account = (await _pca.GetAccountsAsync().ConfigureAwait(false)).Single();
                result = await _pca.AcquireTokenSilent(TestConstants.s_scope, account).ExecuteAsync().ConfigureAwait(false);
                Assert.IsNotNull(result);

                eventDetails = ((TelemetryClient)_telemetryClient).TestTelemetryEventDetails;
                AssertLoggedTelemetry(result, eventDetails, TokenSource.Cache, CacheRefreshReason.NotApplicable);
            }
        }

        private void AssertLoggedTelemetry(AuthenticationResult authenticationResult, MsalTelemetryEventDetails eventDetails, TokenSource tokenSource, CacheRefreshReason cacheRefreshReason)
        {
            Assert.IsNotNull(eventDetails);
            Assert.AreEqual(Convert.ToInt64(cacheRefreshReason), eventDetails.Properties[TelemetryConstants.CacheInfoTelemetry]);
            Assert.AreEqual(Convert.ToInt64(tokenSource), eventDetails.Properties[TelemetryConstants.TokenSource]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationTotalInMs, eventDetails.Properties[TelemetryConstants.Duration]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationInHttpInMs, eventDetails.Properties[TelemetryConstants.DurationInHttp]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationInCacheInMs, eventDetails.Properties[TelemetryConstants.DurationInCache]);
            Assert.AreEqual(authenticationResult.AuthenticationResultMetadata.DurationTotalInMs, eventDetails.Properties[TelemetryConstants.Duration]);
        }

        private PublicClientApplication CreateApplication()
        {
            PublicClientApplication pca = PublicClientApplicationBuilder.Create(TestConstants.ClientId)
                    .WithHttpManager(_harness.HttpManager)
                    .WithDefaultRedirectUri()
                    .WithExperimentalFeatures()
                    .WithTelemetryClient(_telemetryClient)
                    .BuildConcrete();

            TokenCacheHelper.PopulateCache(_pca.UserTokenCacheInternal.Accessor);

            return pca;
        }
    }

    internal class TelemetryClient : ITelemetryClient
    {
        public MsalTelemetryEventDetails TestTelemetryEventDetails { get; set; }
        
        public TelemetryClient(string clientId)
        {
            ClientId = clientId;
        }

        public string ClientId { get; set; }

        public void Initialize()
        {

        }

        public bool IsEnabled()
        {
            return true;
        }

        public bool IsEnabled(string eventName)
        {
            return TelemetryConstants.AcquireTokenEventName.Equals(eventName) ? true : false;
        }

        public void TrackEvent(TelemetryEventDetails eventDetails)
        {
            TestTelemetryEventDetails = (MsalTelemetryEventDetails) eventDetails;
        }

        public void TrackEvent(string eventName, IDictionary<string, string> stringProperties = null, IDictionary<string, long> longProperties = null, IDictionary<string, bool> boolProperties = null, IDictionary<string, DateTime> dateTimeProperties = null, IDictionary<string, double> doubleProperties = null, IDictionary<string, Guid> guidProperties = null)
        {
            throw new NotImplementedException();
        }
    }
}
