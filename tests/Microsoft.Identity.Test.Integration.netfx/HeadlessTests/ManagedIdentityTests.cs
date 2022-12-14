﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Castle.Core.Internal;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Json;
using Microsoft.Identity.Test.Common.Core.Helpers;
using Microsoft.Identity.Test.Integration.NetFx.Infrastructure;
using Microsoft.Identity.Test.LabInfrastructure;
using Microsoft.Identity.Test.Unit;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute.Exceptions;

namespace Microsoft.Identity.Test.Integration.HeadlessTests
{
    [TestClass]
    public class ManagedIdentityTests
    {
        private static readonly string[] s_msi_scopes = { "https://management.azure.com" };
        private static readonly string s_clientId = "client_id";

        //http proxy base URL 
        private static readonly string s_baseURL = "https://service.msidlab.com/";

        //Shared User Assigned Client ID
        private const string UserAssignedClientID = "3b57c42c-3201-4295-ae27-d6baec5b7027";
        
        //Resource ID of the User Assigned Identity 
        private const string Mi_res_id = "/subscriptions/c1686c51-b717-4fe0-9af3-24a20a41fb0c/" +
            "resourcegroups/MSAL_MSI/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" +
            "MSAL_MSI_USERID";

        [TestMethod]
        public async Task ManagedIdentitySourceCheckAsync()
        {
            //Arrange
            string result = string.Empty;
            string expectedClientException = "[Managed Identity] Authentication unavailable. " +
                "No response received from the managed identity endpoint.";

            IConfidentialClientApplication cca = CreateCCAWithProxy(s_baseURL);

            //Act
            try
            {
                AuthenticationResult authenticationResult = await cca
                    .AcquireTokenForClient(s_msi_scopes)
                    .WithManagedIdentity()
                    .ExecuteAsync()
                    .ConfigureAwait(false);
            }
            catch (MsalServiceException ex)
            {
                result = ex.Message;
            }

            //Assert
            Assert.AreSame(result, expectedClientException);
        }

        [DataTestMethod]
        [DataRow(MsiAzureResource.WebApp, "", DisplayName = "System Identity Web App")]
        [DataRow(MsiAzureResource.Function, "", DisplayName = "System Identity Function App")]
        [DataRow(MsiAzureResource.WebApp, UserAssignedClientID, DisplayName = "User Identity Web App")]
        [DataRow(MsiAzureResource.Function, UserAssignedClientID, DisplayName = "User Identity Function App")]
        [DataRow(MsiAzureResource.WebApp, Mi_res_id, DisplayName = "ResourceID Web App")]
        [DataRow(MsiAzureResource.Function, Mi_res_id, DisplayName = "ResourceID Function App")]
        public async Task AcquireMSITokenAsync(MsiAzureResource azureResource, string userIdentity)
        {
            //Arrange
            AuthenticationResult result = null;

            using (new EnvVariableContext())
            {
                //Get the Environment Variables
                Dictionary<string, string> envVariables = 
                    await GetEnvironmentVariablesAsync(azureResource).ConfigureAwait(false);

                //Set the Environment Variables
                SetEnvironmentVariables(envVariables);

                //form the http proxy URI 
                string uri = s_baseURL + $"GetMSIToken?" +
                    $"azureresource={azureResource.ToString().ToLowerInvariant()}&uri=";

                //Create CCA with Proxy
                IConfidentialClientApplication cca = CreateCCAWithProxy(uri);

                //Act
                try
                {
                    result = await cca
                        .AcquireTokenForClient(s_msi_scopes)
                        .WithManagedIdentity(userIdentity)
                        .ExecuteAsync().ConfigureAwait(false);
                }
                catch (MsalClientException ex)
                {
                    throw new Exception(ex.Message);
                }
            
                //Assert
                //1. MSI Helper service trims the access token, so that the access token from the MSI
                //   is not fully returned to the calling service or test for security reasons
                Assert.IsTrue(result.AccessToken.Length == 28);

                //2. First token response is from the MSI Endpoint
                Assert.AreEqual(TokenSource.IdentityProvider, result.AuthenticationResultMetadata.TokenSource);

                //3. Validate the ExpiresOn falls within a 24 hour range from now
                CoreAssert.IsWithinRange(
                                DateTimeOffset.UtcNow + TimeSpan.FromHours(0),
                                result.ExpiresOn,
                                TimeSpan.FromHours(24));

                result = await cca
                    .AcquireTokenForClient(s_msi_scopes)
                    .WithManagedIdentity(userIdentity)
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                //4. Validate the scope
                Assert.IsTrue(s_msi_scopes.All(result.Scopes.Contains));

                //5. Validate the second call to token endpoint gets returned from the cache
                Assert.AreEqual(TokenSource.Cache, result.AuthenticationResultMetadata.TokenSource);
            }
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
            string uri = s_baseURL + "GetEnvironmentVariables?resource=" + resource;

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

        /// <summary>
        /// Create the CCA with the http proxy
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        private IConfidentialClientApplication CreateCCAWithProxy(string url)
        {
            //Proxy the MSI token request 
            ProxyHttpManager proxyHttpManager = new ProxyHttpManager(url);

            ConfidentialClientApplication cca = ConfidentialClientApplicationBuilder
               .Create(s_clientId)
               .WithExperimentalFeatures()
               .WithHttpManager(proxyHttpManager)
               .BuildConcrete();

            return cca;
        }
    }
}