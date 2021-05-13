﻿// -// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;

namespace Microsoft.Identity.Client.Kerberos.Win32
{
#pragma warning disable 618 // This workaround required for Native Win32 API call

    /// <summary>
    /// Provides a layer to interact with the LSA functions used to create logon sessions and manipulate the ticket caches.
    /// </summary>
    public class TicketCacheWriter : IDisposable
    {
        private const string _kerberosPackageName = "Kerberos";
        private const string _negotiatePackageName = "Negotiate";

#if !(iOS || MAC || ANDROID)
        private readonly LsaSafeHandle _lsaHandle;
        private readonly int _selectedAuthPackage;
        private readonly int _negotiateAuthPackage;
        private bool _disposedValue;
#endif

        /*
         * Windows creates a new ticket cache for primary NT tokens. This allows callers to create a dedicated cache for whatever they're doing
         * that way the cache operations like purge or import don't polute the current users cache.
         *
         * To make this work we need to create a new NT token, which is only done during logon. We don't actually want Windows to validate the credentials
         * so we tell it to treat the logon as `NewCredentials` which means Windows will just use those credentials as SSO credentials only.
         *
         * From there a new cache is created and any operations against the "current cache" such as SSPI ISC calls will hit this new cache.
         * We then let callers import tickets into that cache using the krb-cred structure.
         *
         * When done the call to dispose will
         * 1. Revert the impersonation context
         * 2. Close the NT token handle
         * 3. Close the Lsa Handle
         *
         * This destroys the cache and closes the logon session.
         *
         * For any operation that require native allocation and PtrToStructure copies we try and use the CryptoPool mechanism, which checks out a shared
         * pool of memory to create a working for the current operation. On dispose it zeros the memory and returns it to the pool.
         */

        internal unsafe TicketCacheWriter(LsaSafeHandle lsaHandle, string packageName = _kerberosPackageName)
        {
#if (iOS || MAC || ANDROID)
            throw new NotSupportedException("Ticket Cache interface is not supported for this OS platform.");
#else
            this._lsaHandle = lsaHandle;

            var kerberosPackageName = new NativeMethods.LSA_STRING
            {
                Buffer = packageName,
                Length = (ushort)packageName.Length,
                MaximumLength = (ushort)packageName.Length
            };

            var result = NativeMethods.LsaLookupAuthenticationPackage(this._lsaHandle, ref kerberosPackageName, out this._selectedAuthPackage);
            NativeMethods.LsaThrowIfError(result);

            var negotiatePackageName = new NativeMethods.LSA_STRING
            {
                Buffer = _negotiatePackageName,
                Length = (ushort)_negotiatePackageName.Length,
                MaximumLength = (ushort)_negotiatePackageName.Length
            };

            result = NativeMethods.LsaLookupAuthenticationPackage(this._lsaHandle, ref negotiatePackageName, out this._negotiateAuthPackage);
            NativeMethods.LsaThrowIfError(result);
#endif
        }

        /// <summary>
        /// Create a new instance of the interop as a standard unprivileged caller.
        /// </summary>
        /// <param name="package">The name of the LSA authentication package that will be interacted with.</param>
        /// <returns>Returns an instance of the <see cref="TicketCacheWriter"/> class.</returns>
        public static TicketCacheWriter Connect(string package = _kerberosPackageName)
        {
#if (iOS || MAC || ANDROID)
            throw new NotSupportedException("Ticket Cache interface is not supported for this OS platform.");
#else
            if (!KerberosSupplementalTicketManager.IsWindows())
            {
                throw new NotSupportedException("Ticket Cache interface is not supported for this OS platform.");
            }

            if (string.IsNullOrWhiteSpace(package))
            {
                package = _kerberosPackageName;
            }

            var result = NativeMethods.LsaConnectUntrusted(out LsaSafeHandle _lsaHandle);

            NativeMethods.LsaThrowIfError(result);

            return new TicketCacheWriter(_lsaHandle, package);
#endif
        }

        /// <summary>
        /// Import a kerberos ticket containing one or more tickets into the current user ticket cache.
        /// </summary>
        /// <param name="ticketBytes">The ticket to import into the cache.</param>
        /// <param name="luid">The Logon Id of the user owning the ticket cache. The default of 0 represents the currently logged on user.</param>
        public unsafe void ImportCredential(byte[] ticketBytes, long luid = 0)
        {
#if (iOS || MAC || ANDROID)
            throw new NotSupportedException("Ticket Cache interface is not supported for this OS platform.");
#else
            if (ticketBytes is null)
            {
                throw new ArgumentNullException(nameof(ticketBytes));
            }

            var ticketRequest = new NativeMethods.KERB_SUBMIT_TKT_REQUEST
            {
                MessageType = NativeMethods.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage,
                KerbCredSize = ticketBytes.Length,
                KerbCredOffset = Marshal.SizeOf(typeof(NativeMethods.KERB_SUBMIT_TKT_REQUEST)),
                LogonId = luid
            };

            var bufferSize = ticketRequest.KerbCredOffset + ticketBytes.Length;
            IntPtr pBuffer = Marshal.AllocHGlobal(bufferSize);

            Marshal.StructureToPtr(ticketRequest, (IntPtr)pBuffer, false);
            Marshal.Copy(ticketBytes, 0, pBuffer + ticketRequest.KerbCredOffset, ticketBytes.Length);
            this.LsaCallAuthenticationPackage(pBuffer.ToPointer(), bufferSize);
#endif
        }

        /// <summary>
        /// Call Auth package to cache given Kerberos ticket.
        /// </summary>
        /// <param name="pBuffer">Pointer to Kerberos Ticket to cache.</param>
        /// <param name="bufferSize">Length of Kerberos Ticket data.</param>

        private unsafe void LsaCallAuthenticationPackage(void* pBuffer, int bufferSize)
        {
#if !(iOS || MAC || ANDROID)
            LsaBufferSafeHandle returnBuffer = null;

            try
            {
                var result = NativeMethods.LsaCallAuthenticationPackage(
                    this._lsaHandle,
                    this._selectedAuthPackage,
                    pBuffer,
                    bufferSize,
                    out returnBuffer,
                    out int returnBufferLength,
                    out int protocolStatus
                );

                NativeMethods.LsaThrowIfError(result);
                NativeMethods.LsaThrowIfError(protocolStatus);
            }
            finally
            {
                returnBuffer?.Dispose();
            }
#endif
        }

        /// <summary>
        /// Dispose all interment members.
        /// </summary>
        /// <param name="disposing">True if Dispose() called by the user. False, otherwise.</param>
        protected virtual void Dispose(bool disposing)
        {
#if !(iOS || MAC || ANDROID)
            if (!this._disposedValue)
            {
                this._lsaHandle.Dispose();
                this._disposedValue = true;
            }
#endif
        }

        /// <summary>
        /// Deletes current object.
        /// </summary>
        ~TicketCacheWriter()
        {
            this.Dispose(disposing: false);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

#pragma warning restore 618
}
