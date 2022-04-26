﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
#if !NET5_WIN
using Microsoft.Identity.Client.Desktop;
#endif
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Test.Integration.Win8
{
    [TestClass]
    public class BrokerOnWin8Tests
    {
        [TestMethod]
        public void WamOnWin8()
        {
            var pcaBuilder = PublicClientApplicationBuilder
               .Create("d3adb33f-c0de-ed0c-c0de-deadb33fc0d3");
#if !NET5_WIN
            pcaBuilder = pcaBuilder.WithWindowsBroker();
#endif

#pragma warning disable CS0618 // Type or member is obsolete
            Assert.IsFalse(pcaBuilder.IsBrokerAvailable());
#pragma warning restore CS0618 // Type or member is obsolete
        }
    }
}
