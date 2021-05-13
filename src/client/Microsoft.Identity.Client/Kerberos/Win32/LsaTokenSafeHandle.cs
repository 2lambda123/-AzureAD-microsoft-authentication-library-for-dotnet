﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Microsoft.Identity.Client.Kerberos.Win32
{
    internal class LsaTokenSafeHandle : SafeHandle
    {
        public LsaTokenSafeHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public bool Impersonating { get; private set; }

        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            this.Revert();

#if !(iOS || MAC || ANDROID)
            if (!NativeMethods.CloseHandle(this.handle))
            {
                var error = Marshal.GetLastWin32Error();

                throw new Win32Exception(error);
            }
#endif
            return true;
        }

        private void Revert()
        {
            if (!this.Impersonating)
            {
                return;
            }

#if !(iOS || MAC || ANDROID)
            if (!NativeMethods.RevertToSelf())
            {
                var error = Marshal.GetLastWin32Error();

                throw new Win32Exception(error);
            }
#endif
            this.Impersonating = false;
        }
    }
}
