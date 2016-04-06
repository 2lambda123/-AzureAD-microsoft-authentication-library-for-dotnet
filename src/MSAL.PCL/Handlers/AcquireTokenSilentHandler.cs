﻿//----------------------------------------------------------------------
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

using System.Threading.Tasks;
using Microsoft.Identity.Client.Internal;

namespace Microsoft.Identity.Client.Handlers
{
    internal class AcquireTokenSilentHandler : AcquireTokenHandlerBase
    {
        private IPlatformParameters parameters;


        public AcquireTokenSilentHandler(HandlerData handlerData, string userIdentifer, IPlatformParameters parameters, bool forceRefresh) 
            : this(handlerData, (User)null, parameters, forceRefresh)
        {
            this.User = this.MapIdentifierToUser(userIdentifer);
            PlatformPlugin.BrokerHelper.PlatformParameters = parameters;
            this.SupportADFS = false;
        }

        public AcquireTokenSilentHandler(HandlerData handlerData, User user, IPlatformParameters parameters, bool forceRefresh)
            : base(handlerData)
        {
            if (user != null)
            {
                this.User = user;
            }

            PlatformPlugin.BrokerHelper.PlatformParameters = parameters;    
            this.SupportADFS = false;
            this.ForceRefresh = forceRefresh;
        }

        protected override Task<AuthenticationResultEx> SendTokenRequestAsync()
        {
            if (ResultEx == null)
            {
                PlatformPlugin.Logger.Verbose(this.CallState, "No token matching arguments found in the cache");
                throw new MsalSilentTokenAcquisitionException();
            }

            throw new MsalSilentTokenAcquisitionException(ResultEx.Exception);
        }

        protected override void AddAditionalRequestParameters(DictionaryRequestParameters requestParameters)
        {            
        }
    }
}
