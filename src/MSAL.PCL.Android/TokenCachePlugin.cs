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

using Android.App;
using Android.Content;
using System;
using Microsoft.Identity.Client.Interfaces;
using Microsoft.Identity.Client.Internal;

namespace Microsoft.Identity.Client
{
    internal class TokenCachePlugin : ITokenCachePlugin
    {
        private const string SharedPreferencesName = "ActiveDirectoryAuthenticationLibrary";
        private const string SharedPreferencesKey = "cache";

        public IntPtr Handle 
        {
            get { return IntPtr.Zero; }
        }

        public void BeforeAccess(TokenCacheNotificationArgs args)
        {
            if (args.TokenCache.Count > 0)
            {
                // We assume that the cache has not changed since last write
                return;
            }

            try
            {
                ISharedPreferences preferences = Application.Context.GetSharedPreferences(SharedPreferencesName, FileCreationMode.Private);
                string stateString = preferences.GetString(SharedPreferencesKey, null);
                if (stateString != null)
                {
                    byte[] state = Convert.FromBase64String(stateString);
                    args.TokenCache.Deserialize(state);
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
                    ISharedPreferences preferences = Application.Context.GetSharedPreferences(SharedPreferencesName, FileCreationMode.Private);
                    ISharedPreferencesEditor editor = preferences.Edit();
                    editor.Remove(SharedPreferencesKey);

                    if (args.TokenCache.Count > 0)
                    {
                        byte[] state = args.TokenCache.Serialize();
                        string stateString = Convert.ToBase64String(state);
                        editor.PutString(SharedPreferencesKey, stateString);
                    }

                    editor.Apply();
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
