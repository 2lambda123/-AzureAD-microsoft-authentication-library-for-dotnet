﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.Identity.Client.Platforms.Features.DesktopOs.Kerberos
{
    /// <summary>
    /// Result of AcceptSecurityContext (CredSSP) function call which  lets the server component of a transport application
    /// establish a security context between the server and a remote client. 
    /// https://learn.microsoft.com/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext
    /// </summary>
    internal enum ContextStatus
    {
        RequiresContinuation,
        Accepted,
        Error
    }
}
