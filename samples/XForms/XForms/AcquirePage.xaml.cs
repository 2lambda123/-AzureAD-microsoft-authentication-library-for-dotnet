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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Identity.Client;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace XForms
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class AcquirePage : ContentPage
    {
        public IPlatformParameters platformParameters { get; set; }

        public AcquirePage()
        {
            InitializeComponent();
        }

        private void SetPlatformParameters()
        {
            App.PCA.PlatformParameters = platformParameters;
        }

        protected override void OnAppearing()
        {
            SetPlatformParameters();
        }

        private string ToString(User user)
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("user.DisplayableId : " + user.DisplayableId);
            sb.AppendLine("user.IdentityProvider : " + user.IdentityProvider);
            sb.AppendLine("user.Name : " + user.Name);

            return sb.ToString();
        }

        private string ToString(AuthenticationResult result)
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("AccessToken : " + result.AccessToken);
            sb.AppendLine("IdToken : " + result.IdToken);
            sb.AppendLine("ExpiresOn : " + result.ExpiresOn);
            sb.AppendLine("TenantId : " + result.TenantId);
            sb.AppendLine("Scope : " + string.Join(",", result.Scope));
            sb.AppendLine("User :");
            sb.Append(ToString(result.User));

            return sb.ToString();
        }

        private User getUserByDisplayableId(string str)
        {
            var length = App.PCA.Users.Count();
            foreach (User user in App.PCA.Users){
                if (user.DisplayableId.Equals(str))
                {
                    return user;
                }
            }

            return null;
        }

        private async void OnAcquireSilentlyClicked(object sender, EventArgs e)
        {

            if (App.PCA.PlatformParameters == null)
            {
                SetPlatformParameters();
            }
            acquireResponseLabel.Text = "Starting silent token acquisition";
            await Task.Delay(700);

            try
            {
                User user = getUserByDisplayableId(UserEntry.Text.Trim());
                if (user == null)
                {
                    acquireResponseLabel.Text = "User - \"" + UserEntry.Text.Trim() + "\" was not found in the cache";
                    return;
                }
                AuthenticationResult res = await App.PCA.AcquireTokenSilentAsync(App.Scopes, user);

                acquireResponseLabel.Text = ToString(res);
            }
            catch (MsalException exception)
            {
                acquireResponseLabel.Text = "MsalException - " + exception;
            }
            catch (Exception exception)
            {
                acquireResponseLabel.Text = "Exception - " + exception;
            }

        }

        private async void OnAcquireClicked(object sender, EventArgs e)
        {

            if (App.PCA.PlatformParameters == null)
            {
                SetPlatformParameters();
            }

            acquireResponseLabel.Text = "Starting token acquisition";
            await Task.Delay(700);

            try
            {
                AuthenticationResult res;
                if (LoginHint.IsToggled)
                {
                    res = await App.PCA.AcquireTokenAsync(App.Scopes, UserEntry.Text.Trim());

                }
                else
                {
                    res = await App.PCA.AcquireTokenAsync(App.Scopes);
                }

                acquireResponseLabel.Text = ToString(res);
            }
            catch (MsalException exception)
            {
                acquireResponseLabel.Text = "MsalException - " + exception;
            }
            catch (Exception exception)
            {
                acquireResponseLabel.Text = "Exception - " + exception;
            }

        }
    }
}

