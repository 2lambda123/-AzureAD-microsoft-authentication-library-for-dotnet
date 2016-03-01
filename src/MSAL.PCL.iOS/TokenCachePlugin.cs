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

using Foundation;
using Security;
using System;
using Microsoft.Identity.Client.Interfaces;
using Microsoft.Identity.Client.Internal;

namespace Microsoft.Identity.Client
{
    internal class TokenCachePlugin : ITokenCachePlugin
    {
        private const string LocalSettingsContainerName = "ActiveDirectoryAuthenticationLibrary";

        public void BeforeAccess(TokenCacheNotificationArgs args)
        {
            if (args.TokenCache.Count > 0)
            {
                // We assume that the cache has not changed since last write
                return;
            }

            try
            {
                SecStatusCode res;
                var rec = new SecRecord(SecKind.GenericPassword)
                {
                    Generic = NSData.FromString(LocalSettingsContainerName),
                    Accessible = SecAccessible.Always,
                    Service = "MSAL.PCL.iOS Service",
                    Account = "MSAL.PCL.iOS cache",
                    Label = "MSAL.PCL.iOS Label",
                    Comment = "MSAL.PCL.iOS Cache",
                    Description = "Storage for cache"
                };

                var match = SecKeyChain.QueryAsRecord(rec, out res);
                if (res == SecStatusCode.Success && match != null && match.ValueData != null)
                {
                    byte[] dataBytes = match.ValueData.ToArray();
                    if (dataBytes != null)
                    {
                        args.TokenCache.Deserialize(dataBytes);
                    }
                }
            }
            catch (Exception ex)
            {
                PlatformPlugin.Logger.Warning(null, "Failed to load cache: " + ex);
                // Ignore as the cache seems to be corrupt
            }
        }
        
        public void AfterAccess(TokenCacheNotificationArgs args)
        {
            if (args.TokenCache.HasStateChanged)
            {
                try
                {
                    var s = new SecRecord(SecKind.GenericPassword)
                    {
                        Generic = NSData.FromString(LocalSettingsContainerName),
	                Accessible = SecAccessible.Always,
                        Service = "ADAL.PCL.iOS Service",
                        Account = "ADAL.PCL.iOS cache",
                        Label = "ADAL.PCL.iOS Label",
                        Comment = "ADAL.PCL.iOS Cache",
                        Description = "Storage for cache"
                    };

                    var err = SecKeyChain.Remove(s);
                    if (args.TokenCache.Count > 0)
                    {
                        s.ValueData = NSData.FromArray(args.TokenCache.Serialize());
                        err = SecKeyChain.Add(s);
                    }

                    args.TokenCache.HasStateChanged = false;
                }
                catch (Exception ex)
                {
                    PlatformPlugin.Logger.Warning(null, "Failed to save cache: " + ex);
                }
            }
        }
    }
}
