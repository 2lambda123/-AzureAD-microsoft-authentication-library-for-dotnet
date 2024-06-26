﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Windows.Forms;

namespace Microsoft.Identity.Client.Desktop.WebView2WebUi
{

    internal class Win32Window : IWin32Window
    {
        public Win32Window(IntPtr handle)
        {
            Handle = handle;
        }
        public IntPtr Handle { get; }

    }
}
