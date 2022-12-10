﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Client.Utils;

namespace Microsoft.Identity.Client
{
    internal class MsalServiceExceptionFactory
    {
        static readonly ISet<string> s_nonUiSubErrors = new HashSet<string>(
            new[] { MsalError.ClientMismatch, MsalError.ProtectionPolicyRequired },
            StringComparer.OrdinalIgnoreCase);

        internal static MsalServiceException FromHttpResponse(
          string errorCode,
          string errorMessage,
          HttpResponse httpResponse,
          Exception innerException = null)
        {
            MsalServiceException ex = null;
            var oAuth2Response = JsonHelper.TryToDeserializeFromJson<OAuth2ResponseBase>(httpResponse?.Body);

            if (IsInvalidGrant(oAuth2Response?.Error, oAuth2Response?.SubError) || IsInteractionRequired(oAuth2Response?.Error))
            {
                if (IsThrottled(oAuth2Response))
                {
                    ex = new MsalUiRequiredException(errorCode, MsalErrorMessage.AadThrottledError, innerException);
                }
                else
                {
                    ex = new MsalUiRequiredException(errorCode, errorMessage, innerException);
                }
            }

            if (string.Equals(oAuth2Response?.Error, MsalError.InvalidClient, StringComparison.OrdinalIgnoreCase))
            {
                ex = new MsalServiceException(
                    MsalError.InvalidClient,
                    MsalErrorMessage.InvalidClient + " Original exception: " + oAuth2Response?.ErrorDescription,
                    innerException);
            }

            ex ??= new MsalServiceException(errorCode, errorMessage, innerException);

            SetHttpExceptionData(ex, httpResponse);

            ex.Claims = oAuth2Response?.Claims;
            ex.CorrelationId = oAuth2Response?.CorrelationId;
            ex.SubError = oAuth2Response?.SubError;

            return ex;
        }

        private static bool IsThrottled(OAuth2ResponseBase oAuth2Response)
        {
            return oAuth2Response.ErrorDescription != null &&
               oAuth2Response.ErrorDescription.StartsWith(Constants.AadThrottledErrorCode);
        }

        internal static MsalServiceException FromImdsResponse(
          string errorCode,
          string errorMessage,
          HttpResponse httpResponse,
          Exception innerException = null)
        {
            MsalServiceException ex = new MsalServiceException(errorCode, errorMessage, innerException);

            SetHttpExceptionData(ex, httpResponse);

            return ex;
        }

        internal static MsalThrottledServiceException FromThrottledAuthenticationResponse(HttpResponse httpResponse)
        {
            MsalServiceException ex = new MsalServiceException(MsalError.RequestThrottled, MsalErrorMessage.AadThrottledError);
            SetHttpExceptionData(ex, httpResponse);
            return new MsalThrottledServiceException(ex);
        }

        protected static void SetHttpExceptionData(MsalServiceException ex, HttpResponse httpResponse)
        {
            ex.ResponseBody = httpResponse?.Body;
            ex.StatusCode = httpResponse != null ? (int)httpResponse.StatusCode : 0;
            ex.Headers = httpResponse?.Headers;
        }

        protected static bool IsInteractionRequired(string errorCode)
        {
            return string.Equals(errorCode, MsalError.InteractionRequired, StringComparison.OrdinalIgnoreCase);
        }

        protected static bool IsInvalidGrant(string errorCode, string subErrorCode)
        {
            return string.Equals(errorCode, MsalError.InvalidGrantError, StringComparison.OrdinalIgnoreCase)
                             && IsInvalidGrantSubError(subErrorCode);
        }

        private static bool IsInvalidGrantSubError(string subError)
        {
            if (string.IsNullOrEmpty(subError))
            {
                return true;
            }

            return !s_nonUiSubErrors.Contains(subError);
        }
    }
}
