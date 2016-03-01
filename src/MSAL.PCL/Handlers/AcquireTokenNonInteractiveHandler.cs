﻿//----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Internal;

namespace Microsoft.Identity.Client.Handlers
{
    internal class AcquireTokenNonInteractiveHandler : AcquireTokenHandlerBase
    {
        private readonly UserCredential userCredential;
        private UserAssertion userAssertion;
        
        public AcquireTokenNonInteractiveHandler(HandlerData handlerData, UserCredential userCredential)
            : base(handlerData)
        {
            if (userCredential == null)
            {
                throw new ArgumentNullException("userCredential");
            }

            this.userCredential = userCredential;
        }

        public AcquireTokenNonInteractiveHandler(HandlerData handlerData, UserAssertion userAssertion)
            : base(handlerData)
        {
            if (userAssertion == null)
            {
                throw new ArgumentNullException("userAssertion");
            }

            if (string.IsNullOrWhiteSpace(userAssertion.AssertionType))
            {
                throw new ArgumentException(MsalErrorMessage.UserCredentialAssertionTypeEmpty, "userAssertion");
            }

            this.userAssertion = userAssertion;
        }

        internal override async Task PreRunAsync()
        {
            await base.PreRunAsync().ConfigureAwait(false);

            if (this.userCredential != null)
            {
                if (string.IsNullOrWhiteSpace(this.userCredential.UserName))
                {
                    this.userCredential.UserName = await PlatformPlugin.PlatformInformation.GetUserPrincipalNameAsync().ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(userCredential.UserName))
                    {
                        PlatformPlugin.Logger.Information(this.CallState, "Could not find UPN for logged in user");
                        throw new MsalException(MsalError.UnknownUser);
                    }

                    PlatformPlugin.Logger.Verbose(this.CallState, string.Format("Logged in user with hash '{0}' detected", PlatformPlugin.CryptographyHelper.CreateSha256Hash(userCredential.UserName)));
                }

                this.User = new User { DisplayableId = userCredential.UserName};
            }
            else if (this.userAssertion != null)
            {
                this.User = new User { DisplayableId = userAssertion.UserName };
            }
        }

        internal override async Task PreTokenRequest()
        {
            await base.PreTokenRequest().ConfigureAwait(false);
            if (this.PerformUserRealmDiscovery())
            {
                UserRealmDiscoveryResponse userRealmResponse = await UserRealmDiscoveryResponse.CreateByDiscoveryAsync(this.Authenticator.UserRealmUri, this.userCredential.UserName, this.CallState).ConfigureAwait(false);
                PlatformPlugin.Logger.Information(this.CallState, string.Format("User with hash '{0}' detected as '{1}'", PlatformPlugin.CryptographyHelper.CreateSha256Hash(this.userCredential.UserName), userRealmResponse.AccountType));

                if (string.Compare(userRealmResponse.AccountType, "federated", StringComparison.OrdinalIgnoreCase) == 0)
                {
                    if (string.IsNullOrWhiteSpace(userRealmResponse.FederationMetadataUrl))
                    {
                        throw new MsalException(MsalError.MissingFederationMetadataUrl);
                    }

                    WsTrustAddress wsTrustAddress = await MexParser.FetchWsTrustAddressFromMexAsync(userRealmResponse.FederationMetadataUrl, this.userCredential.UserAuthType, this.CallState).ConfigureAwait(false);
                    PlatformPlugin.Logger.Information(this.CallState, string.Format("WS-Trust endpoint '{0}' fetched from MEX at '{1}'", wsTrustAddress.Uri, userRealmResponse.FederationMetadataUrl));

                    WsTrustResponse wsTrustResponse = await WsTrustRequest.SendRequestAsync(wsTrustAddress, this.userCredential, this.CallState).ConfigureAwait(false);
                    PlatformPlugin.Logger.Information(this.CallState, string.Format("AccessToken of type '{0}' acquired from WS-Trust endpoint", wsTrustResponse.TokenType));

                    // We assume that if the response token type is not SAML 1.1, it is SAML 2
                    this.userAssertion = new UserAssertion(wsTrustResponse.Token, (wsTrustResponse.TokenType == WsTrustResponse.Saml1Assertion) ? OAuthGrantType.Saml11Bearer : OAuthGrantType.Saml20Bearer, this.userCredential.UserName);
                }
                else
                {
                    throw new MsalException(MsalError.UnsupportedUserType);
                }
            }
        }

        protected override void AddAditionalRequestParameters(DictionaryRequestParameters requestParameters)
        {
            if (this.userAssertion != null)
            {
                requestParameters[OAuthParameter.GrantType] = this.userAssertion.AssertionType;
                requestParameters[OAuthParameter.Assertion] = Convert.ToBase64String(Encoding.UTF8.GetBytes(this.userAssertion.Assertion));
            }
        }
        
        private bool PerformUserRealmDiscovery()
        {
            // To decide whether user realm discovery is needed or not
            // we should also consider if that is supported by the authority
            return this.userAssertion == null &&
                   this.SupportADFS == false;
        }
    }
}
