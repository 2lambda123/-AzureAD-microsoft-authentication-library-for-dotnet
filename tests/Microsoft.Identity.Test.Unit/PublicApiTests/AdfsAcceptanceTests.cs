﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Test.Common.Core.Mocks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Unit.PublicApiTests
{
    [TestClass]
    public class AdfsAcceptanceTests : TestBase
    {
        // Possible authorities copied from: https://msazure.visualstudio.com/One/_search?action=contents&text=CanAcquireToken_UsingRefreshToken&type=code&lp=code-Project&filters=ProjectFilters%7BOne%7DRepositoryFilters%7BAzureStack-Services-Graph%7D&pageSize=25&result=DefaultCollection/One/AzureStack-Services-Graph/GBmain//src/Identity.Web.Tests/MsalTests.cs
        [DataTestMethod]
        [DataRow("https://localhost:3001/adfs")]
        [DataRow("https://localhost:3001/460afc9d-718d-40c8-8d03-954")]
        [DataRow("https://localhost:3001/contoso.int.test")]
        public async Task AdfsAuthorityVariants_WithAdfsAuthority_Async(string authority)
        {
            await RunAuthCodeFlowAsync(authority, useWithAdfsAuthority: true).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("https://localhost:3001/adfs")]
        [DataRow("https://localhost:3001/460afc9d-718d-40c8-8d03-954")]
        [DataRow("https://localhost:3001/contoso.int.test")]
        public async Task AdfsAuthorityVariants_WithAuthority_Async(string authority)
        {
            await RunAuthCodeFlowAsync(authority, useWithAdfsAuthority: false).ConfigureAwait(false);
        }

        private static async Task RunAuthCodeFlowAsync(string authority, bool useWithAdfsAuthority)
        {
            using (var httpManager = new MockHttpManager())
            {
                // specific client id used by the id token in AddAdfsWithTenantIdMockHandler
                var builder = ConfidentialClientApplicationBuilder
                    .Create("e68c40a5-a8e5-4250-bbea-5b43ab18cf0d");

                builder = useWithAdfsAuthority ?
                    builder.WithAdfsAuthority(authority, false) :
                    builder.WithAuthority(authority, false);

                var app = builder
                    .WithRedirectUri("http://localhost")
                    .WithHttpManager(httpManager)
                    .WithInstanceDiscovery(false)
                    .WithClientSecret(TestConstants.ClientSecret)
                    .Build();


                httpManager.AddAdfsWithTenantIdMockHandler();

                var result = await app.AcquireTokenByAuthorizationCode(new[] { "https://arm.asz/.default" }, "authcode")
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                var account = await app.GetAccountAsync(result.Account.HomeAccountId.Identifier).ConfigureAwait(false);

                AssertAdfsResult(result, account);

                var result2 = await app.AcquireTokenSilent(new[] { "https://arm.asz/.default" }, account)
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                var account2 = await app.GetAccountAsync(result.Account.HomeAccountId.Identifier).ConfigureAwait(false);
                AssertAdfsResult(result2, account2);
                Assert.AreEqual(TokenSource.Cache, result2.AuthenticationResultMetadata.TokenSource);
            }
        }

        private static void AssertAdfsResult(AuthenticationResult result, IAccount account)
        {
            Assert.AreEqual("460afc9d-718d-40c8-8d03-9540fa56cc2c", result.TenantId);
            Assert.AreEqual("460afc9d-718d-40c8-8d03-9540fa56cc2c", result.ClaimsPrincipal.FindFirst("tid").Value);

            Assert.AreEqual("localhost", account.Environment);
            Assert.AreEqual("admin@demo.asz", account.Username);
            Assert.AreEqual("FTiFcJ97JrNoywo4SSdQjA", account.HomeAccountId.Identifier);
            Assert.AreEqual("FTiFcJ97JrNoywo4SSdQjA", account.HomeAccountId.ObjectId);
            Assert.IsNull(account.HomeAccountId.TenantId);
            Assert.IsNull(account.GetTenantProfiles());
        }
    }
}
