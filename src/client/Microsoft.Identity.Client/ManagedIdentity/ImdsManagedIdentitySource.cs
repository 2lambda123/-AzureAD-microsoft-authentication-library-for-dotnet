﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Client.Internal;

namespace Microsoft.Identity.Client.ManagedIdentity
{
    /// <summary>
    /// Original source of code: https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/identity/Azure.Identity/src/ImdsManagedIdentitySource.cs
    /// </summary>
    internal class ImdsManagedIdentitySource : ManagedIdentitySource
    {
        // IMDS constants. Docs for IMDS are available here https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token#get-a-token-using-http
        private static readonly Uri s_imdsEndpoint = new("http://169.254.169.254/metadata/identity/oauth2/token");

        private const string ImdsTokenPath = "/metadata/identity/oauth2/token";
        private const string ImdsApiVersion = "2018-02-01";
        private const string DefaultMessage = "[Managed Identity] Service request failed.";

        internal const string IdentityUnavailableError = "[Managed Identity] Authentication unavailable. The requested identity has not been assigned to this resource.";
        internal const string GatewayError = "[Managed Identity] Authentication unavailable. The request failed due to a gateway error.";

        private readonly string _clientId;
        private readonly string _resourceId;
        private readonly Uri _imdsEndpoint;

        internal ImdsManagedIdentitySource(RequestContext requestContext) : base(requestContext)
        {
            if (!string.IsNullOrEmpty(EnvironmentVariables.PodIdentityEndpoint))
			{
                requestContext.Logger.Verbose("[Managed Identity] Environment variable for IMDS returned endpoint: " + EnvironmentVariables.PodIdentityEndpoint);
                var builder = new UriBuilder(EnvironmentVariables.PodIdentityEndpoint)
                {
                    Path = ImdsTokenPath
                };
                _imdsEndpoint = builder.Uri;
			}
			else
			{
                requestContext.Logger.Verbose("[Managed Identity] Unable to find AZURE_POD_IDENTITY_AUTHORITY_HOST environment variable for IMDS, using the default endpoint.");
            	_imdsEndpoint = s_imdsEndpoint;
			}

            _clientId = requestContext.ServiceBundle.Config.ManagedIdentityUserAssignedClientId;
            _resourceId = requestContext.ServiceBundle.Config.ManagedIdentityUserAssignedResourceId;
        }

        protected override ManagedIdentityRequest CreateRequest(string resource)
        {
            ManagedIdentityRequest request = new(HttpMethod.Get, _imdsEndpoint);

            request.Headers.Add("Metadata", "true");
            request.QueryParameters["api-version"] = ImdsApiVersion;
            request.QueryParameters["resource"] = resource;

            if (!string.IsNullOrEmpty(_clientId))
            {
                _requestContext.Logger.Verbose("[Managed Identity] Adding user assigned client id to the request.");
                request.QueryParameters[Constants.ManagedIdentityClientId] = _clientId;
            }
            else if (!string.IsNullOrEmpty(_resourceId))
            {
                _requestContext.Logger.Verbose("[Managed Identity] Adding user assigned resource id to the request.");
                request.QueryParameters[Constants.ManagedIdentityResourceId] = _resourceId;
            }

            return request;
        }

        public override async Task<ManagedIdentityResponse> AuthenticateAsync(AppTokenProviderParameters parameters, CancellationToken cancellationToken)
        {
            try
            {
                return await base.AuthenticateAsync(parameters, cancellationToken).ConfigureAwait(false);
            }
            catch (TaskCanceledException)
            {
                _requestContext.Logger.Error(TimeoutError);
                throw;
            }
        }

        protected override ManagedIdentityResponse HandleResponse(
            AppTokenProviderParameters parameters, 
            HttpResponse response)
        {
            // handle error status codes indicating managed identity is not available
            var baseMessage = response.StatusCode switch
            {
                HttpStatusCode.BadRequest => IdentityUnavailableError,
                HttpStatusCode.BadGateway => GatewayError,
                HttpStatusCode.GatewayTimeout => GatewayError,
                _ => default(string)
            };

            if (baseMessage != null)
            {
                string message = CreateRequestFailedMessage(response, baseMessage);

                var errorContentMessage = GetMessageFromErrorResponse(response);

                message = message + Environment.NewLine + errorContentMessage;

                _requestContext.Logger.Error($"Error message: {message} Http status code: {response.StatusCode}");
                throw new MsalServiceException(MsalError.ManagedIdentityRequestFailed, message);
            }

            // Default behavior to handle successful scenario and general errors.
            return base.HandleResponse(parameters, response);
        }

        internal static string CreateRequestFailedMessage(HttpResponse response, string message)
        {
            StringBuilder messageBuilder = new StringBuilder();

            messageBuilder
                .AppendLine(message ?? DefaultMessage)
                .Append("Status: ")
                .Append(response.StatusCode.ToString());

            if (response.Body != null)
            {
                messageBuilder
                    .AppendLine()
                    .AppendLine("Content:")
                    .AppendLine(response.Body);
            }

            messageBuilder
                .AppendLine()
                .AppendLine("Headers:");

            foreach (var header in response.HeadersAsDictionary)
            {
                messageBuilder.AppendLine($"{header.Key}: {header.Value}");
            }

            return messageBuilder.ToString();
        }
    }
}
