﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Castle.Core.Internal;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AuthScheme;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Json;
using Microsoft.Identity.Test.Common.Core.Helpers;
using Microsoft.Identity.Test.Integration.NetFx.Infrastructure;
using Microsoft.Identity.Test.LabInfrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Microsoft.Identity.Test.Common.Core.Helpers.ManagedIdentityTestUtil;

namespace Microsoft.Identity.Test.E2E.NetStandard
{
    [TestClass]
    public class ManagedIdentityAppService
    {
        private static readonly string s_msi_scopes = "https://management.azure.com";

        //http proxy base URL 
        private static readonly string s_baseURL = "https://msimsalintegration.azurewebsites.net/";

        //Shared User Assigned Client ID
        private const string UserAssignedClientID = "3b57c42c-3201-4295-ae27-d6baec5b7027";

        //Resource ID of the User Assigned Identity 
        private const string UamiResourceId = "/subscriptions/c1686c51-b717-4fe0-9af3-24a20a41fb0c/" +
            "resourcegroups/MSAL_MSI/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" +
            "MSAL_MSI_USERID";

        [DataTestMethod]
        [DataRow(MsiAzureResource.WebApp, "", DisplayName = "System Identity Web App")]
        [DataRow(MsiAzureResource.WebApp, UserAssignedClientID, DisplayName = "User Identity Web App")]
        [DataRow(MsiAzureResource.WebApp, UamiResourceId, DisplayName = "Resource Identity Web App")]
        public async Task AcquireMSITokenAsync(MsiAzureResource azureResource, string userIdentity)
        {
            //Arrange
            using (new EnvVariableContext())
            {
                // Fetch the environment variables from the resource and set them locally
                Dictionary<string, string> envVariables =
                    await GetEnvironmentVariablesAsync(azureResource).ConfigureAwait(false);

                //Set the Environment Variables
                SetEnvironmentVariables(envVariables);

                //form the http proxy URI 
                string uri = s_baseURL + $"MSIToken?" +
                    $"azureresource={azureResource}&uri=";

                //Create CCA with Proxy
                IManagedIdentityApplication mia = CreateMIAWithProxy(uri, userIdentity);

                AuthenticationResult result = null;
                //Act
                result = await mia
                            .AcquireTokenForManagedIdentity(s_msi_scopes)
                            .ExecuteAsync().ConfigureAwait(false);

                //Assert
                //1. Token Type
                Assert.AreEqual("Bearer", result.TokenType);

                //2. First token response is from the MSI Endpoint
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);

                //3. Validate the ExpiresOn falls within a 24 hour range from now
                CoreAssert.IsWithinRange(
                                DateTimeOffset.UtcNow + TimeSpan.FromHours(0),
                                result.ExpiresOn,
                                TimeSpan.FromHours(24));

                result = await mia
                    .AcquireTokenForManagedIdentity(s_msi_scopes)
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                //4. Validate the scope
                Assert.IsTrue(result.Scopes.All(s_msi_scopes.Contains));

                //5. Validate the second call to token endpoint gets returned from the cache
                Assert.AreEqual(TokenSource.Cache,
                    result.AuthenticationResultMetadata.TokenSource);
            }
        }

        /// <summary>
        /// Create the CCA with the http proxy
        /// </summary>
        /// <param name="url"></param>
        /// <param name="userAssignedId"></param>
        /// <returns></returns>
        private IManagedIdentityApplication CreateMIAWithProxy(string url, string userAssignedId = "")
        {
            //Proxy the MSI token request 
            MsiProxyHttpManager proxyHttpManager = new MsiProxyHttpManager(url);

            var builder = ManagedIdentityApplicationBuilder
               .Create()
               .WithExperimentalFeatures()
               .WithHttpManager(proxyHttpManager);

            if (!string.IsNullOrEmpty(userAssignedId))
            {
                builder = ManagedIdentityApplicationBuilder
               .Create(userAssignedId)
               .WithExperimentalFeatures()
               .WithHttpManager(proxyHttpManager);
            }

            IManagedIdentityApplication mia = builder.Build();

            return mia;
        }

        /// <summary>
        /// Gets the environment variable
        /// </summary>
        /// <param name="resource"></param>
        /// <returns></returns>
        private async Task<Dictionary<string, string>> GetEnvironmentVariablesAsync(
            MsiAzureResource resource)
        {
            Dictionary<string, string> environmentVariables = new Dictionary<string, string>();

            //Get the Environment Variables from the MSI Helper Service
            string uri = s_baseURL + "EnvironmentVariables?resource=" + resource;

            var environmentVariableResponse = await LabUserHelper
                .GetMSIEnvironmentVariablesAsync(uri)
                .ConfigureAwait(false);

            //process the response
            if (!string.IsNullOrEmpty(environmentVariableResponse))
            {
                environmentVariables = JsonConvert.DeserializeObject
                    <Dictionary<string, string>>(environmentVariableResponse);
            }

            return environmentVariables;
        }

        /// <summary>
        /// Sets the Environment Variables
        /// </summary>
        /// <param name="envVariables"></param>
        private void SetEnvironmentVariables(Dictionary<string, string> envVariables)
        {
            //Set the environment variables
            foreach (KeyValuePair<string, string> kvp in envVariables)
            {
                Environment.SetEnvironmentVariable(kvp.Key, kvp.Value);
            }
        }
    }
}