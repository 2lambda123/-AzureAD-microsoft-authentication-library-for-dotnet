﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.TelemetryCore
{
    internal enum AssertionType
    {
        None = 0,
        CertificateWithoutSni = 1,
        CertificateWithSni = 2,
        Secret = 3,
        ClientAssertion = 4,
        Msi = 5
    }
}
