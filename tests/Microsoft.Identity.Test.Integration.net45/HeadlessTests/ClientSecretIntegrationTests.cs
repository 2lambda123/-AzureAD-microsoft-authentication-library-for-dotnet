﻿//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------


using Microsoft.Azure.KeyVault.Models;
using Microsoft.Identity.Client;
using Microsoft.Identity.Test.Common;
using Microsoft.Identity.Test.LabInfrastructure;
using Microsoft.Identity.Test.Unit;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity.Test.Integration.HeadlessTests
{
    [TestClass]
    public class ClientSecretIntegrationTests
    {
        private static string[] s_adfsScopes = { string.Format(CultureInfo.CurrentCulture, "{0}/email openid", Adfs2019LabConstants.AppId) };

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        [TestInitialize]
        public void TestInitialize()
        {
            TestCommon.ResetInternalStaticCaches();
        }

        [TestMethod]
        [TestCategory("ClientSecretIntegrationTests")]
        public async Task AcquireTokenWithClientSecretFromAdfsAsync()
        {
            KeyVaultSecretsProvider secretProvider = new KeyVaultSecretsProvider();
            SecretBundle secret = secretProvider.GetSecret(Adfs2019LabConstants.ADFS2019ClientSecretURL);

            ConfidentialClientApplication msalConfidentialClient = ConfidentialClientApplicationBuilder.Create(Adfs2019LabConstants.ConfidentialClientId)
                                            .WithAdfsAuthority(Adfs2019LabConstants.Authority, true)
                                            .WithRedirectUri(Adfs2019LabConstants.ClientRedirectUri)
                                            .WithClientSecret(secret.Value)
                                            .BuildConcrete();

            //AuthenticationResult authResult = await msalConfidentialClient.AcquireTokenForClientAsync(AdfsScopes).ConfigureAwait(false);
            AuthenticationResult authResult = await msalConfidentialClient.AcquireTokenForClient(s_adfsScopes).ExecuteAsync().ConfigureAwait(false);
            Assert.IsNotNull(authResult);
            Assert.IsNotNull(authResult.AccessToken);
            Assert.IsNull(authResult.IdToken);
        }

    }
}
