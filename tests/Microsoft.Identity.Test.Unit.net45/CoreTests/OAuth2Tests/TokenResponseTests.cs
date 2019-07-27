﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Client.TelemetryCore;
using Microsoft.Identity.Test.Common.Core.Mocks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Unit.CoreTests.OAuth2Tests
{
    [TestClass]
    public class TokenResponseTests : TestBase
    {
        [TestMethod]
        public void ExpirationTimeTest()
        {
            // Need to get timestamp here since it needs to be before we create the token.
            // ExpireOn time is calculated from UtcNow when the object is created.
            DateTimeOffset current = DateTimeOffset.UtcNow;
            const long ExpiresInSeconds = 3599;

            var response = TestConstants.CreateMsalTokenResponse();

            Assert.IsTrue(response.AccessTokenExpiresOn.Subtract(current) >= TimeSpan.FromSeconds(ExpiresInSeconds));
        }

        [TestMethod]
        public void JsonDeserializationTest()
        {
            using (var harness = CreateTestHarness())
            {
                harness.HttpManager.AddSuccessTokenResponseMockHandlerForPost(TestConstants.AuthorityCommonTenant);

                OAuth2Client client = new OAuth2Client(harness.ServiceBundle.DefaultLogger, harness.HttpManager, new TelemetryManager(
                    harness.ServiceBundle.Config,
                    harness.ServiceBundle.PlatformProxy,
                    null));

                Task<MsalTokenResponse> task = client.GetTokenAsync(
                    new Uri(TestConstants.AuthorityCommonTenant + "oauth2/v2.0/token"),
                    new RequestContext(harness.ServiceBundle, Guid.NewGuid()));
                MsalTokenResponse response = task.Result;
                Assert.IsNotNull(response);
            }
        }
    }
}
