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
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Widget;
using Android.OS;
using Microsoft.Identity.Client;
using TestApp.PCL;

namespace AndroidTestApp
{
    [Activity(Label = "AndroidTestApp", MainLauncher = true, Icon = "@drawable/icon")]
    public class MainActivity : Activity
    {
        private TextView accessTokenTextView;
        private MobileAppSts sts = new MobileAppSts();
        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);

            // Set our view from the "main" layout resource
            SetContentView(Resource.Layout.Main);

            Button acquireTokenInteractiveButton = FindViewById<Button>(Resource.Id.acquireTokenInteractiveButton);
            acquireTokenInteractiveButton.Click += acquireTokenInteractiveButton_Click;

            Button acquireTokenSilentButton = FindViewById<Button>(Resource.Id.acquireTokenSilentButton);
            acquireTokenSilentButton.Click += acquireTokenSilentButton_Click;

            Button clearCacheButton = FindViewById<Button>(Resource.Id.clearCacheButton);
            clearCacheButton.Click += clearCacheButton_Click;

            this.accessTokenTextView = FindViewById<TextView>(Resource.Id.accessTokenTextView);

            sts.Authority = "https://login.microsoftonline.com/common";
            sts.ValidClientId = "b92e0ba5-f86e-4411-8e18-6b5f928d968a";
            sts.ValidScope = new [] { "https://msdevex-my.sharepoint.com"};
            sts.ValidUserName = "mam@msdevex.onmicrosoft.com";

            EditText email = FindViewById<EditText>(Resource.Id.email);
            email.Text = sts.ValidUserName;
        }
        
        private async void acquireTokenSilentButton_Click(object sender, EventArgs e)
        {
            this.accessTokenTextView.Text = string.Empty;
            TokenBroker tokenBroker = new TokenBroker();
            tokenBroker.Sts = sts;
            EditText email = FindViewById<EditText>(Resource.Id.email);
            tokenBroker.Sts.ValidUserName = email.Text;
            string value = null;
            try
            {
                value = await tokenBroker.GetTokenSilentAsync(new PlatformParameters(this)).ConfigureAwait(false);
            }
            catch (Java.Lang.Exception ex)
            {
                throw new Exception(ex.Message + "\n" + ex.StackTrace);
            }
            catch (Exception exc)
            {
                value = exc.Message;
            }

            this.accessTokenTextView.Text = value;

        }

        private async void acquireTokenInteractiveButton_Click(object sender, EventArgs e)
        {
            this.accessTokenTextView.Text = string.Empty;
            TokenBroker tokenBroker = new TokenBroker();
            tokenBroker.Sts = sts;
            EditText email = FindViewById<EditText>(Resource.Id.email);
            tokenBroker.Sts.ValidUserName = email.Text;
            string value = null;
            try
            {
                //value = await tokenBroker.GetTokenInteractiveAsync(new PlatformParameters(this)).ConfigureAwait(false);
            }
            catch (Java.Lang.Exception ex)
            {
                throw new Exception(ex.Message + "\n" + ex.StackTrace);
            }
            catch (Exception exc)
            {
                value = exc.Message;
            }

            this.accessTokenTextView.Text = value;
        }

        private async void clearCacheButton_Click(object sender, EventArgs e)
        {
            await Task.Factory.StartNew(() =>
            {
                TokenCache.DefaultSharedUserTokenCache.Clear(sts.ValidClientId);
                this.accessTokenTextView.Text = "Cache cleared";
            }).ConfigureAwait(false);
        }
    }
}

