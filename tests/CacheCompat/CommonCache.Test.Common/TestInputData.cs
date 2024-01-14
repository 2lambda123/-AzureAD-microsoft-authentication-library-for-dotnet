﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace CommonCache.Test.Common
{
    public class TestInputData
    {
        public const string MsGraph = "https://graph.microsoft.com";

        public List<LabUserData> LabUserDatas { get; set; }
        public string ResultsFilePath { get; set; }
        public CacheStorageType StorageType { get; set; }
    }
}
