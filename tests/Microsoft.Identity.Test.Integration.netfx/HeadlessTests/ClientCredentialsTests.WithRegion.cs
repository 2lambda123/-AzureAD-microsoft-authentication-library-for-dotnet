﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Cache;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.TelemetryCore;
using Microsoft.Identity.Test.Common;
using Microsoft.Identity.Test.Integration.net45.Infrastructure;
using Microsoft.Identity.Test.Integration.NetFx.Infrastructure;
using Microsoft.Identity.Test.LabInfrastructure;
using Microsoft.Identity.Test.Unit;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Integration.HeadlessTests
{
    [TestClass]
    public class RegionalAuthIntegrationTests
    {
        private KeyVaultSecretsProvider _keyVault;
        private Dictionary<string, string> _dict = new Dictionary<string, string>
        {
            ["allowestsrnonmsi"] = "true"
        };

        private const string RegionalHost = "centralus.r.login.microsoftonline.com";
        private const string GlobalHost = "login.microsoftonline.com";
        private IConfidentialClientApplication _confidentialClientApplication;


        [TestInitialize]
        public void TestInitialize()
        {
            TestCommon.ResetInternalStaticCaches();

            if (_keyVault == null)
            {
                _keyVault = new KeyVaultSecretsProvider();
            }
        }

        [TestCleanup]
        public void TestCleanup()
        {
            Environment.SetEnvironmentVariable(TestConstants.RegionName, null);
        }

        [TestMethod]
        public async Task AcquireTokenToRegionalEndpointAsync()
        {
            // Arrange
            var factory = new HttpSnifferClientFactory();
            var settings = ConfidentialAppSettings.GetSettings(Cloud.Public);
            _confidentialClientApplication = BuildCCA(settings, factory);

            Environment.SetEnvironmentVariable(TestConstants.RegionName, TestConstants.Region);
            AuthenticationResult result = await GetAuthenticationResultAsync(settings.AppScopes).ConfigureAwait(false); // regional endpoint
            AssertTokenSourceIsIdp(result);
            AssertValidHost(true, factory);
            AssertTelemetry(factory, $"{TelemetryConstants.HttpTelemetrySchemaVersion}|1004,{CacheInfoTelemetry.NoCachedAT:D},centralus,3,4|0,1");
        }

        [TestMethod]
        public async Task RequestGoesToUserSpecifiedRegion_Async()
        {
            // Arrange
            var factory = new HttpSnifferClientFactory();
            var settings = ConfidentialAppSettings.GetSettings(Cloud.Public);
            _confidentialClientApplication = BuildCCA(settings, factory, true, "westus");

            Environment.SetEnvironmentVariable(TestConstants.RegionName, TestConstants.Region);
            AuthenticationResult result = await GetAuthenticationResultAsync(settings.AppScopes).ConfigureAwait(false); // regional endpoint
            AssertTokenSourceIsIdp(result);
            Assert.AreEqual(
              "https://westus.r.login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token?allowestsrnonmsi=true",
              factory.RequestsAndResponses.Single().Item1.RequestUri.ToString());

            AssertTelemetry(factory, $"{TelemetryConstants.HttpTelemetrySchemaVersion}|1004,{CacheInfoTelemetry.NoCachedAT:D},westus,3,3|0,1");

            _confidentialClientApplication = BuildCCA(settings, factory, true, TestConstants.Region);
            result = await GetAuthenticationResultAsync(settings.AppScopes, withForceRefresh: true).ConfigureAwait(false); // regional endpoint
            AssertTokenSourceIsIdp(result);
            AssertValidHost(true, factory, 1);
            AssertTelemetry(factory, $"{TelemetryConstants.HttpTelemetrySchemaVersion}|1004,{CacheInfoTelemetry.ForceRefresh:D},centralus,2,1|0,1", 1);
        }

        private void AssertTelemetry(HttpSnifferClientFactory factory, string currentTelemetryHeader, int placement = 0)
        {
            var (req, res) = factory.RequestsAndResponses.Skip(placement).Single();
            Assert.AreEqual(currentTelemetryHeader, req.Headers.GetValues("x-client-current-telemetry").First());
        }

        private void AssertValidHost(
          bool isRegionalHost,
          HttpSnifferClientFactory factory,
          int placement = 0)
        {
            if (isRegionalHost)
            {
                var (req, res) = factory.RequestsAndResponses.Skip(placement).Single(x => x.Item1.RequestUri.Host == RegionalHost && x.Item2.StatusCode == HttpStatusCode.OK);
                Assert.AreEqual(RegionalHost, req.RequestUri.Host);
            }
            else
            {
                var (req, res) = factory.RequestsAndResponses.Skip(placement).Single(x => x.Item1.RequestUri.Host == GlobalHost && x.Item2.StatusCode == HttpStatusCode.OK);
                Assert.AreEqual(GlobalHost, req.RequestUri.Host);
            }
        }

        private void AssertTokenSourceIsIdp(
           AuthenticationResult result)
        {
            Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);
        }

        private IConfidentialClientApplication BuildCCA(
            IConfidentialAppSettings settings,
            HttpSnifferClientFactory factory,
            bool useClaims = false,
            string region = ConfidentialClientApplication.AttemptRegionDiscovery)
        {
            var builder = ConfidentialClientApplicationBuilder.Create(settings.ClientId);
            if (useClaims)
            {
                builder.WithClientAssertion(GetSignedClientAssertionUsingMsalInternal(settings.ClientId, GetClaims(settings)));
            }
            else
            {
                builder.WithCertificate(settings.GetCertificate());
            }

            builder.WithAuthority($@"https://{settings.Environment}/{settings.TenantId}")
                .WithTestLogging()
                .WithExperimentalFeatures(true)
                .WithHttpClientFactory(factory);

            if (region != null)
            {
                builder.WithAzureRegion(region);
            }

            return builder.Build();
        }

        private async Task<AuthenticationResult> GetAuthenticationResultAsync(
            string[] scope,
            bool withForceRefresh = false)
        {
            var result = await _confidentialClientApplication.AcquireTokenForClient(scope)
                            .WithExtraQueryParameters(_dict)
                            .WithForceRefresh(withForceRefresh)
                            .ExecuteAsync()
                            .ConfigureAwait(false);

            Assert.IsNotNull(result);
            Assert.IsNotNull(result.AccessToken);
            return result;
        }

        internal static long ConvertToTimeT(DateTime time)
        {
            var startTime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            TimeSpan diff = time - startTime;
            return (long)diff.TotalSeconds;
        }

        private static IDictionary<string, string> GetClaims(IConfidentialAppSettings settings)
        {
            DateTime validFrom = DateTime.UtcNow;
            var nbf = ConvertToTimeT(validFrom);
            var exp = ConvertToTimeT(validFrom + TimeSpan.FromSeconds(TestConstants.JwtToAadLifetimeInSeconds));

            return new Dictionary<string, string>()
                {
                { "aud", $"https://{settings.Environment}/{settings.TenantId}/v2.0" },
                { "exp", exp.ToString(CultureInfo.InvariantCulture) },
                { "iss", settings.ClientId },
                { "jti", Guid.NewGuid().ToString() },
                { "nbf", nbf.ToString(CultureInfo.InvariantCulture) },
                { "sub", settings.ClientId },
                { "ip", "192.168.2.1" }
                };

        }

        private static string GetSignedClientAssertionUsingMsalInternal(string clientId, IDictionary<string, string> claims)
        {
#if NET_CORE
            var manager = new Client.Platforms.netcore.NetCoreCryptographyManager();
#else
                    var manager = new Client.Platforms.net45.NetDesktopCryptographyManager();
#endif
            var jwtToken = new Client.Internal.JsonWebToken(manager, clientId, TestConstants.ClientCredentialAudience, claims);
            var clientCredential = ClientCredentialWrapper.CreateWithCertificate(GetCertificate(), claims);
            return jwtToken.Sign(clientCredential, false);
        }

        private static X509Certificate2 GetCertificate(bool useRSACert = false)
        {
            X509Certificate2 cert = CertificateHelper.FindCertificateByThumbprint(useRSACert ?
                TestConstants.RSATestCertThumbprint :
                TestConstants.AutomationTestThumbprint);
            if (cert == null)
            {
                throw new InvalidOperationException(
                    "Test setup error - cannot find a certificate in the My store for KeyVault. This is available for Microsoft employees only.");
            }

            return cert;
        }
    }
}
