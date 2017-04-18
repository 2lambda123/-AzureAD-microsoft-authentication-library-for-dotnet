﻿//----------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// This exception class is to inform developers that UI interaction is required for authentication to 
    /// succeed.
    /// </summary>
    public class MsalUiRequiredException : MsalException
    {
        /// <summary>
        /// Standard OAuth2 protocol error code. It indicates to the libray that the user needs to go the UI for 
        /// getting a new token.
        /// </summary>
        public static readonly string InvalidGrantError = "invalid_grant";

        /// <summary>
        /// No tokens were found matching the criteria.
        /// </summary>
        public static readonly string NoTokensFoundError = "no_tokens_found";

        /// <summary>
        /// This error code comes back from AcquireTokenSilent calls when null token cache reference 
        /// is passed into the application constructor
        /// </summary>
        public static readonly string TokenCacheNullError = "token_cache_null";

        /// <summary>
        /// One of two conditions was encountered.
        /// 1. The PromptBehavior.Never flag was passed and but the constraint could not be honored
        /// because user interaction was required.
        /// 2. An error occurred during a silent web authentication that prevented the authentication
        /// flow from completing in a short enough time frame.
        /// </summary>
        public static readonly string NoPromptFailedError = "no_prompt_failed";

        /// <summary>
        /// Initializes a new instance of the exception class with a specified
        /// error code.
        /// </summary>
        /// <param name="errorCode">
        /// The error code returned by the service or generated by client. This is the code you can rely on
        /// for exception handling.
        /// </param>
        public MsalUiRequiredException(string errorCode) : base(errorCode)
        {
        }

        /// <summary>
        /// Initializes a new instance of the exception class with a specified
        /// error code and error message.
        /// </summary>
        /// <param name="errorCode">
        /// The error code returned by the service or generated by client. This is the code you can rely on
        /// for exception handling.
        /// </param>
        /// <param name="errorMessage">The error message that explains the reason for the exception.</param>
        public MsalUiRequiredException(string errorCode, string errorMessage):base(errorCode, errorMessage)
        {
        }

        /// <summary>
        /// Initializes a new instance of the exception class with a specified
        /// error code, error message and inner exception indicating the root cause.
        /// </summary>
        /// <param name="errorCode">
        /// The error code returned by the service or generated by client. This is the code you can rely on
        /// for exception handling.
        /// </param>
        /// <param name="errorMessage">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">Represents the root cause of the exception.</param>
        public MsalUiRequiredException(string errorCode, string errorMessage, Exception innerException):base(errorCode, errorMessage, innerException)
        {
        }
    }
}
