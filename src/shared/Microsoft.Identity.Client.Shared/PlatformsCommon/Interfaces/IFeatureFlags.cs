﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.Identity.Client.Internal.Interfaces
{
    internal interface IFeatureFlags
    {
        bool IsFociEnabled { get; }
    }
}
