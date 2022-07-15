﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.ServiceEssentials;

namespace Microsoft.Identity.Client.Cache.Prototype
{
    internal class DefaultInMemoryCache : IIdentityCache
    {
        private readonly MemoryCache _memoryCache;

        public DefaultInMemoryCache(CacheOptions cacheOptions)
        {
            _memoryCache = new MemoryCache(new MemoryCacheOptions() { SizeLimit = cacheOptions?.SizeLimit ?? 1000 });
        }

        public Task<CacheEntry<T>> GetAsync<T>(string category, string key, CancellationToken cancellationToken = default) where T : ICacheObject
        {
            CacheEntry<T> result = null;
            _memoryCache?.TryGetValue(key, out result);
            return Task.FromResult(result);
        }

        public Task SetAsync<T>(string category, string key, T value, CacheEntryOptions cacheEntryOptions, CancellationToken cancellationToken = default) where T : ICacheObject
        {
            var cacheEntry = new CacheEntry<T>(value, cacheEntryOptions.ExpirationTimeUTC, cacheEntryOptions.RefreshTimeUTC);
            var memoryCacheOptions = new MemoryCacheEntryOptions()
            {
                AbsoluteExpiration = cacheEntryOptions.ExpirationTimeUTC,
                Size = 1
            };
            _memoryCache.Set(key, cacheEntry, memoryCacheOptions);
            return Task.CompletedTask;
        }

        #region Not Implemented
        public Task RemoveAsync(string category, string key, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        public Task<CacheEntry<string>> GetAsync(string category, string key, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task SetAsync(string category, string key, string value, CacheEntryOptions cacheEntryOptions, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
