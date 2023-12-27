﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
#if !NET7_WIN
using Microsoft.Identity.Client.Broker;
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
#if !NET7_WIN
            pcaBuilder = pcaBuilder.WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows) { Title = "Only Windows" });
#endif

            Assert.IsFalse(pcaBuilder.IsBrokerAvailable());
        }
    }
}
