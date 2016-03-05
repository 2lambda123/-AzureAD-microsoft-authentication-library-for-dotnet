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

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// Secret including client id and secret.
    /// </summary>
    public sealed class ClientCredential
    {

        /// <summary>
        /// Constructor to create Secret with client id and secret
        /// </summary>
        /// <param name="credential">Secret of the client requesting the token.</param>
        public ClientCredential(IClientAssertionCertificate certificate)
        {
            this.Certificate = certificate;
        }

        /// <summary>
        /// Constructor to create Secret with client id and secret
        /// </summary>
        /// <param name="secret">Secret of the client requesting the token.</param>
        public ClientCredential(string secret)
        {

            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new ArgumentNullException("secret");
            }
            
            this.Secret = secret;
        }

        internal string Secret { get; private set; }

        internal IClientAssertionCertificate Certificate { get; private set; }

        internal  ClientAssertion ClientAssertion { get; set; }

        internal long ValidTo { get; set; }
    }
}
