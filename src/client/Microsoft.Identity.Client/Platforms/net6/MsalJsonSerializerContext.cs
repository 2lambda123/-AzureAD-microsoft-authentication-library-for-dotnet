﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Identity.Client.Cache;
using Microsoft.Identity.Client.Instance.Discovery;
using Microsoft.Identity.Client.Instance.Oidc;
using Microsoft.Identity.Client.Instance.Validation;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.Kerberos;
using Microsoft.Identity.Client.ManagedIdentity;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Client.Region;
using Microsoft.Identity.Client.WsTrust;

namespace Microsoft.Identity.Client.Platforms.net6
{
#pragma warning disable CS0534 // OneBranchSuppression for 'MsalJsonSerializerContext' does not implement inherited abstract member 'JsonSerializerContext.GeneratedSerializerOptions.get'
    /// <summary>
    /// This class specifies metadata for System.Text.Json source generation.
    /// See <see href="https://docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-source-generation-modes?pivots=dotnet-6-0">https://docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-source-generation-modes?pivots=dotnet-6-0</see>
    /// and <see href="https://docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-source-generation?pivots=dotnet-6-0">How to use source generation in System.Text.Json </see> for official docs.
    /// </summary>
    [JsonSerializable(typeof(KerberosSupplementalTicket))]
    [JsonSerializable(typeof(InstanceDiscoveryResponse))]
    [JsonSerializable(typeof(LocalImdsErrorResponse))]
    [JsonSerializable(typeof(AdalResultWrapper))]
    [JsonSerializable(typeof(List<KeyValuePair<string, IEnumerable<string>>>))]
    [JsonSerializable(typeof(ClientInfo))]
    [JsonSerializable(typeof(OAuth2ResponseBase))]
    [JsonSerializable(typeof(MsalTokenResponse))]
    [JsonSerializable(typeof(UserRealmDiscoveryResponse))]
    [JsonSerializable(typeof(DeviceCodeResponse))]
    [JsonSerializable(typeof(AdfsWebFingerResponse))]
    [JsonSerializable(typeof(JsonWebToken.JWTHeaderWithCertificate))]
    [JsonSerializable(typeof(JsonWebToken.JWTPayload))]
    [JsonSerializable(typeof(DeviceAuthHeader))]
    [JsonSerializable(typeof(DeviceAuthPayload))]
    [JsonSerializable(typeof(ManagedIdentityResponse))]
    [JsonSerializable(typeof(ManagedIdentityErrorResponse))]
    [JsonSerializable(typeof(OidcMetadata))]
    [JsonSourceGenerationOptions]
    internal partial class MsalJsonSerializerContext : JsonSerializerContext
    {
        private static MsalJsonSerializerContext s_customContext;

        public static MsalJsonSerializerContext Custom
        {
            get
            {
                return s_customContext ??=
                    new MsalJsonSerializerContext(new JsonSerializerOptions
                    {
                        NumberHandling = JsonNumberHandling.AllowReadingFromString,
                        AllowTrailingCommas = true,
                        Converters =
                        {
                            new JsonStringConverter(),
                        }
                    });
            }
        }
    }
}
