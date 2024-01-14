﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.Identity.Client.PlatformsCommon.Shared
{
    internal class PKeyAuthConstants
    {
        public const string DeviceAuthHeaderName = "x-ms-PKeyAuth";
        public const string DeviceAuthHeaderValue = "1.0";
        public const string WwwAuthenticateHeader = "WWW-Authenticate";
        public const string PKeyAuthName = "PKeyAuth";
        public const string ChallengeResponseContext = "Context";
        public const string ChallengeResponseVersion = "Version";
        public const string PKeyAuthBypassReponseFormat = @"PKeyAuth Context=""{0}"",Version=""{1}""";
    }
}
