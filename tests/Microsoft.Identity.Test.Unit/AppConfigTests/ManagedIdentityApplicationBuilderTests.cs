﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Drawing.Text;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.Internal.ClientCredential;
using Microsoft.Identity.Test.Common;
using Microsoft.Identity.Test.Common.Core.Helpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Unit.AppConfigTests
{
    [TestClass]
    [TestCategory(TestCategories.BuilderTests)]
    public class ManagedIdentityApplicationBuilderTests
    {
        [TestInitialize]
        public void TestInitialize()
        {
            TestCommon.ResetInternalStaticCaches();
        }

        [TestMethod]
        public void TestConstructor()
        {
            var mi = ManagedIdentityApplicationBuilder.Create()
                .WithExperimentalFeatures().Build();

            // Assert defaults
            Assert.AreEqual(Constants.ManagedIdentityDefaultClientId, mi.AppConfig.ClientId);
            Assert.AreEqual(Constants.DefaultConfidentialClientRedirectUri, mi.AppConfig.RedirectUri);

            Assert.IsNotNull(mi.UserTokenCache);
            Assert.IsNotNull(mi.AppConfig.ClientName);
            Assert.IsNotNull(mi.AppConfig.ClientVersion);

            Assert.IsNull(mi.AppConfig.HttpClientFactory);
            Assert.IsNull(mi.AppConfig.LoggingCallback);
            Assert.IsNull(mi.AppConfig.TenantId);

            // Validate Defaults
            Assert.AreEqual(LogLevel.Info, mi.AppConfig.LogLevel);
            Assert.AreEqual(false, mi.AppConfig.EnablePiiLogging);
            Assert.AreEqual(false, mi.AppConfig.IsDefaultPlatformLoggingEnabled);
        }

        [TestMethod]
        public void TestConstructor_WithCreateUserAssignedId()
        {
            var mi = ManagedIdentityApplicationBuilder.Create(TestConstants.ClientId)
                .WithExperimentalFeatures().BuildConcrete();

            // Assert defaults
            Assert.AreEqual(TestConstants.ClientId, mi.AppConfig.ClientId);
            Assert.AreEqual(Constants.DefaultConfidentialClientRedirectUri, mi.AppConfig.RedirectUri);

            Assert.IsNotNull(mi.UserTokenCache);
            Assert.IsNotNull(mi.AppConfig.ClientName);
            Assert.IsNotNull(mi.AppConfig.ClientVersion);

            Assert.IsNotNull(mi.ServiceBundle.Config.ManagedIdentityUserAssignedClientId);
            Assert.AreEqual(TestConstants.ClientId, mi.ServiceBundle.Config.ManagedIdentityUserAssignedClientId);

            Assert.IsNull(mi.AppConfig.HttpClientFactory);
            Assert.IsNull(mi.AppConfig.LoggingCallback);
            Assert.IsNull(mi.AppConfig.TenantId);

            // Validate Defaults
            Assert.AreEqual(LogLevel.Info, mi.AppConfig.LogLevel);
            Assert.AreEqual(false, mi.AppConfig.EnablePiiLogging);
            Assert.AreEqual(false, mi.AppConfig.IsDefaultPlatformLoggingEnabled);
        }

        [DataTestMethod]
        [DataRow(TestConstants.ClientId)]
        [DataRow("resourceId", false)]
        [DataRow("resourceId/subscription", false)]
        public void TestConstructor_WithUserAssignedManagedIdentity_ResourceId(string userAssignedId, bool isClientId = true)
        {
            var mi = ManagedIdentityApplicationBuilder.Create(userAssignedId)
                .WithExperimentalFeatures()
                .BuildConcrete();

            if (isClientId)
            {
                Assert.AreEqual(userAssignedId, mi.AppConfig.ClientId);
                Assert.IsNotNull(mi.ServiceBundle.Config.ManagedIdentityUserAssignedClientId);
                Assert.AreEqual(userAssignedId, mi.ServiceBundle.Config.ManagedIdentityUserAssignedClientId);
            }
            else
            {
                Assert.AreEqual(Constants.ManagedIdentityDefaultClientId + userAssignedId.GetHashCode(), mi.AppConfig.ClientId);
                Assert.IsNotNull(mi.ServiceBundle.Config.ManagedIdentityUserAssignedResourceId);
                Assert.AreEqual(userAssignedId, mi.ServiceBundle.Config.ManagedIdentityUserAssignedResourceId);
            }
        }

        [DataTestMethod]
        [DataRow(false, false, false)]
        [DataRow(true, true, true)]
        [DataRow(true, false, false)]
        [DataRow(false, true, true)]
        public void CacheSynchronizationNoDefault(bool optionFlag, bool builderFlag, bool result)
        {
            var options = new ManagedIdentityApplicationOptions
            {
                UserAssignedClientId = TestConstants.ClientId,
                EnableCacheSynchronization = optionFlag
            };
            var mi = ManagedIdentityApplicationBuilder.CreateWithApplicationOptions(options).WithExperimentalFeatures()
                .WithCacheSynchronization(builderFlag).Build();
            Assert.AreEqual(result, (mi.AppConfig as ApplicationConfiguration).CacheSynchronizationEnabled);
        }

        [TestMethod]
        public void TestConstructor_WithDebugLoggingCallback()
        {
            var mi = ManagedIdentityApplicationBuilder.Create()
                .WithExperimentalFeatures()
                .WithDebugLoggingCallback()
                .Build();
            Assert.IsNotNull(mi.AppConfig.LoggingCallback);
        }

        [TestMethod]
        public void TestConstructor_WithHttpClientFactory()
        {
            var httpClientFactory = NSubstitute.Substitute.For<IMsalHttpClientFactory>();
            var mi = ManagedIdentityApplicationBuilder.Create()
                .WithExperimentalFeatures()
                .WithHttpClientFactory(httpClientFactory)
                .Build();
            Assert.AreEqual(httpClientFactory, mi.AppConfig.HttpClientFactory);
        }

        [TestMethod]
        public void TestConstructor_WithLogging()
        {
            var mi = ManagedIdentityApplicationBuilder
                .Create()
                .WithExperimentalFeatures()
                .WithLogging((level, message, pii) => { }).Build();

            Assert.IsNotNull(mi.AppConfig.LoggingCallback);
        }

    }
}
