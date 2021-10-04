﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// Options for MSAL token caches. 
    /// </summary>
    /// <remarks>
    /// These option do not allow configuration of external cache serialization, for which you should use <see cref="TokenCache.SetAfterAccessAsync(System.Func{TokenCacheNotificationArgs, System.Threading.Tasks.Task})"/> and other callbacks.
    /// For detailed recommendations see: https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-net-token-cache-serialization?tabs=aspnetcore
    /// </remarks>
    public class CacheOptions
    {
        /// <summary>
        /// Recommended options for using a static cache. 
        /// </summary>
        /// <remarks>
        /// May include some eviction policies in the future to keep memory in check.
        /// </remarks>
        public static CacheOptions EnableSharedCacheOptions
        {
            get
            {
                return new CacheOptions(true);
            }
        }

        /// <summary>
        /// Constructor for the options with default values.
        /// </summary>
        public CacheOptions()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="useSharedCache">Set to true to share the cache between all ClientApplication objects. The cache becomes static. <see cref="UseSharedCache"/> for a detailed description. </param>
        public CacheOptions(bool useSharedCache)
        {
            UseSharedCache = useSharedCache;
        }

        /// <summary>
        /// Share the cache between all ClientApplication objects. The cache becomes static. Defaults to false.
        /// </summary>
        /// <remarks>
        /// Recommended only for client credentials flow (service to service communication).
        /// Web apps and Web APIs should use external token caching (Redis, Cosmos etc.) for scaling purposes.
        /// Desktop apps should encrypt and persist their token cache to disk, to avoid losing tokens when app restarts. 
        /// ADAL used a static cache by default.
        /// </remarks>
        public bool UseSharedCache { get; set; }

    }
}
