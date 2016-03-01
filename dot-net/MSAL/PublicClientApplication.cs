﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Handlers;
using Microsoft.Identity.Client.Interfaces;
using Microsoft.Identity.Client.Internal;

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// Native applications (desktop/phone/iOS/Android).
    /// </summary>
    public sealed class PublicClientApplication : AbstractClientApplication
    {
        private const string DEFAULT_CLIENT_ID = "default-client-id";
        private const string DEFAULT_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob";

        /// <summary>
        /// Default consutructor of the application.
        /// </summary>
        public PublicClientApplication():this(DefaultAuthority)
        {
        }

        public PublicClientApplication(string authority):this(authority, DEFAULT_CLIENT_ID)
        {
        }

        public PublicClientApplication(string authority, string clientId) : base(authority, clientId, DEFAULT_REDIRECT_URI, true)
        {
            this.UserTokenCache = TokenCache.DefaultSharedUserTokenCache;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scope"></param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string[] scope)
        {
            Authenticator authenticator = new Authenticator(this.Authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenCommonAsync(authenticator, scope, null, new Uri(this.RedirectUri), (string) null,
                        UiOptions.SelectAccount, null, null).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="identifier"></param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string[] scope, string identifier)
        {
            Authenticator authenticator = new Authenticator(this.Authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenCommonAsync(authenticator, scope, null, new Uri(this.RedirectUri), identifier,
                        UiOptions.SelectAccount, null, null).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="identifier"></param>
        /// <param name="extraQueryParameters"></param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string[] scope, string identifier,
            UiOptions options, string extraQueryParameters)
        {
            Authenticator authenticator = new Authenticator(this.Authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenCommonAsync(authenticator, scope, null, new Uri(this.RedirectUri), identifier,
                        options, extraQueryParameters, null).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="identifier"></param>
        /// <param name="extraQueryParameters"></param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string[] scope, User user,
            UiOptions options, string extraQueryParameters)
        {
            Authenticator authenticator = new Authenticator(this.Authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenCommonAsync(authenticator, scope, null, new Uri(this.RedirectUri), user, options,
                        extraQueryParameters, null).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="identifier"></param>
        /// <param name="extraQueryParameters"></param>
        /// <param name="options"></param>
        /// <param name="additionalScope"></param>
        /// <param name="authority"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string[] scope, string identifier,
            UiOptions options, string extraQueryParameters, string[] additionalScope, string authority, string policy)
        {
            Authenticator authenticator = new Authenticator(authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenCommonAsync(authenticator, scope, additionalScope, new Uri(this.RedirectUri),
                        identifier, options, extraQueryParameters, policy).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="identifier"></param>
        /// <param name="extraQueryParameters"></param>
        /// <param name="options"></param>
        /// <param name="additionalScope"></param>
        /// <param name="authority"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string[] scope, User user,
            UiOptions options, string extraQueryParameters, string[] additionalScope, string authority, string policy)
        {
            Authenticator authenticator = new Authenticator(authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenCommonAsync(authenticator, scope, additionalScope, new Uri(this.RedirectUri), user,
                        options, extraQueryParameters, policy).ConfigureAwait(false);
        }
        
        internal IWebUI CreateWebAuthenticationDialog(IPlatformParameters parameters)
        {
            return PlatformPlugin.WebUIFactory.CreateAuthenticationDialog(parameters);
        }
        
        /// <summary>
        /// .NET specific method for intergrated auth. To support Xamarin, we would need to move these to platform specific libraries.
        /// </summary>
        /// <param name="scope"></param>
        /// <returns></returns>
        internal async Task<AuthenticationResult> AcquireTokenWithIntegratedAuthInternalAsync(string[] scope)
        {
            Authenticator authenticator = new Authenticator(this.Authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenUsingIntegratedAuthCommonAsync(authenticator, scope,
                        new UserCredential(), null).ConfigureAwait(false);
        }

        /// <summary>
        /// .NET specific method for intergrated auth. To support Xamarin, we would need to move these to platform specific libraries.
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="authority"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        internal async Task<AuthenticationResult> AcquireTokenWithIntegratedAuthInternalAsync(string[] scope, string authority, string policy)
        {
            Authenticator authenticator = new Authenticator(authority, this.ValidateAuthority, this.CorrelationId);
            return
                await
                    this.AcquireTokenUsingIntegratedAuthCommonAsync(authenticator, scope,
                        new UserCredential(), policy).ConfigureAwait(false);
        }

        private async Task<AuthenticationResult> AcquireTokenUsingIntegratedAuthCommonAsync(Authenticator authenticator, string[] scope, UserCredential userCredential, string policy)
        {
            var handler = new AcquireTokenNonInteractiveHandler(this.GetHandlerData(authenticator, scope, policy, this.UserTokenCache), userCredential);
            return await handler.RunAsync().ConfigureAwait(false);
        }


        /// <summary>
        /// interactive call using login_hint
        /// </summary>
        /// <param name="authenticator"></param>
        /// <param name="scope"></param>
        /// <param name="additionalScope"></param>
        /// <param name="clientId"></param>
        /// <param name="redirectUri"></param>
        /// <param name="loginHint"></param>
        /// <param name="uiOptions"></param>
        /// <param name="extraQueryParameters"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        private async Task<AuthenticationResult> AcquireTokenCommonAsync(Authenticator authenticator, string[] scope, string[] additionalScope, Uri redirectUri, string loginHint, UiOptions uiOptions, string extraQueryParameters, string policy)
        {
            if (this.PlatformParameters == null)
            {
                this.PlatformParameters = PlatformPlugin.DefaultPlatformParameters;
            }

            var handler =
                new AcquireTokenInteractiveHandler(
                    this.GetHandlerData(authenticator, scope, policy, this.UserTokenCache), additionalScope, redirectUri,
                    this.PlatformParameters, loginHint, uiOptions, extraQueryParameters,
                    this.CreateWebAuthenticationDialog(this.PlatformParameters));
            return await handler.RunAsync().ConfigureAwait(false);
        }

        /// <summary>
        /// interactive call using User object.
        /// </summary>
        /// <param name="authenticator"></param>
        /// <param name="scope"></param>
        /// <param name="additionalScope"></param>
        /// <param name="clientId"></param>
        /// <param name="redirectUri"></param>
        /// <param name="loginHint"></param>
        /// <param name="uiOptions"></param>
        /// <param name="extraQueryParameters"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        private async Task<AuthenticationResult> AcquireTokenCommonAsync(Authenticator authenticator, string[] scope, string[] additionalScope, Uri redirectUri, User user, UiOptions uiOptions, string extraQueryParameters, string policy)
        {
            if (this.PlatformParameters == null)
            {
                this.PlatformParameters = PlatformPlugin.DefaultPlatformParameters;
            }

            var handler =
                new AcquireTokenInteractiveHandler(
                    this.GetHandlerData(authenticator, scope, policy, this.UserTokenCache), additionalScope, redirectUri,
                    this.PlatformParameters, user, uiOptions, extraQueryParameters,
                    this.CreateWebAuthenticationDialog(this.PlatformParameters));
            return await handler.RunAsync().ConfigureAwait(false);
        }

        internal override HandlerData GetHandlerData(Authenticator authenticator, string[] scope, string policy,
            TokenCache cache)
        {
            HandlerData data = base.GetHandlerData(authenticator, scope, policy, cache);
            data.ClientKey = new ClientKey(this.ClientId);

            return data;
        }

    }
}