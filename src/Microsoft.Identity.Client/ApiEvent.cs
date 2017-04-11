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


using Microsoft.Identity.Client.Internal;

namespace Microsoft.Identity.Client
{
    internal class ApiEvent : EventBase
    {
        public ApiEvent() : base(EventNamePrefix + "api_event") {}

        public int ApiId
        {
            set => this["api_id"] = value.ToString();
        }

        public string Authority
        {
            set => this["authority"] = value;
        }

        public string AuthorityType
        {
            set => this["authority_type"] = value;
        }

        public string UiBehavior
        {
            set => this["ui_behavior"] = value;
        }

        public string ValidationStatus
        {
            set => this["validation_status"] = value;
        }

        public string TenantId
        {
            set => this["tenant_id"] = PlatformPlugin.CryptographyHelper.CreateBase64UrlEncodedSha256Hash(value);
        }

        public string UserId
        {
            set => this["user_id"] = PlatformPlugin.CryptographyHelper.CreateBase64UrlEncodedSha256Hash(value);
        }

        public bool WasSuccessful
        {
            set => this["was_successful"] = value.ToString();
        }
    }
}
