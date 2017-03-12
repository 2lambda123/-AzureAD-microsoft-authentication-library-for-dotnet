﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.Features
{
    /// <summary>
    /// Indicates how AcquireToken should prompt the user.
    /// </summary>
    public partial struct UIOptions
    {
        /// <summary>
        /// Only available on .NET platform. AcquireToken will send prompt=attempt_none to 
        /// authorize endpoint and the library uses a hidden webview to authenticate the user.
        /// </summary>
        public readonly static UIOptions Never = new UIOptions("attempt_none");
    }
}
