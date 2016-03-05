//----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

using System.Collections.Generic;
using System.Reflection;

namespace Microsoft.Identity.Client.Internal
{
    internal static class MsalIdParameter
    {
        /// <summary>
        /// ADAL Flavor: .NET or WinRT
        /// </summary>
        public const string Product = "x-client-SKU";

        /// <summary>
        /// ADAL assembly version
        /// </summary>
        public const string Version = "x-client-Ver";

        /// <summary>
        /// CPU platform with x86, x64 or ARM as value
        /// </summary>
        public const string CpuPlatform = "x-client-CPU";

        /// <summary>
        /// Version of the operating system. This will not be sent on WinRT
        /// </summary>
        public const string OS = "x-client-OS";

        /// <summary>
        /// Device model. This will not be sent on .NET
        /// </summary>
        public const string DeviceModel = "x-client-DM";
    }

    /// <summary>
    /// This class adds additional query parameters or headers to the requests sent to STS. This can help us in
    /// collecting statistics and potentially on diagnostics.
    /// </summary>
    internal static class MsalIdHelper
    {
        public static IDictionary<string, string> GetMsalIdParameters()
        {
            var parameters = new Dictionary<string, string>();

            parameters[MsalIdParameter.Product] = PlatformPlugin.PlatformInformation.GetProductName();
            parameters[MsalIdParameter.Version] = GetMsalVersion();

            var processorInofrmation = PlatformPlugin.PlatformInformation.GetProcessorArchitecture();
            if (processorInofrmation != null)
            {
                parameters[MsalIdParameter.CpuPlatform] = processorInofrmation;
            }

            var osInformation = PlatformPlugin.PlatformInformation.GetOperatingSystem();
            if (osInformation != null)
            {
                parameters[MsalIdParameter.OS] = osInformation;
            }

            var deviceInformation = PlatformPlugin.PlatformInformation.GetDeviceModel();
            if (deviceInformation != null)
            {
                parameters[MsalIdParameter.DeviceModel] = deviceInformation;
            }

            return parameters;
        }

        public static string GetMsalVersion()
        {
            return typeof(MsalIdHelper).GetTypeInfo().Assembly.GetName().Version.ToString();
        }

        public static string GetAssemblyFileVersion()
        {
            return PlatformPlugin.PlatformInformation.GetAssemblyFileVersionAttribute();
        }

        public static string GetAssemblyInformationalVersion()
        {
            AssemblyInformationalVersionAttribute attribute = typeof(MsalIdHelper).GetTypeInfo().Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
            return (attribute != null) ? attribute.InformationalVersion : string.Empty;
        }
    }
}