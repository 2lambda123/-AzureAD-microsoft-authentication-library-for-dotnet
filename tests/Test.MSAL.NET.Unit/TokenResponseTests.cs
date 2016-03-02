﻿using System;
using System.Net;
using Microsoft.Identity.Client.Interfaces;
using Microsoft.Identity.Client.Internal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace Test.MSAL.NET.Unit
{
    [TestClass]
    public class TokenResponseTests
    {
        [TestMethod]
        [TestCategory("TokenResponseTests")]
        public void CreateErrorResponseTest()
        {
            var webResponse = Substitute.For<IHttpWebResponse>();
            
            TokenResponse response = TokenResponse.CreateFromErrorResponse(null);
            Assert.IsNotNull(response);
            Assert.AreEqual(MsalError.ServiceReturnedError, response.Error);
            Assert.AreEqual(MsalErrorMessage.ServiceReturnedError, response.ErrorDescription);

            using (
                var stream =
                    MockHelpers.GenerateStreamFromString(
                        "{ \"expires_in\":\"3599\",\"token_type\":\"Bearer\",\"scope\":\"https://outlook.office.com/Mail.Read\",\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJodHRwczovL291dGxvb2sub2ZmaWNlLmNvbSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzY5MmFkZWNmLWVjZmItNDRmZS05YTIyLTdjN2YyNDMwNjAwMi8iLCJpYXQiOjE0MzQxMzEyNTksIm5iZiI6MTQzNDEzMTI1OSwiZXhwIjoxNDM0MTM1MTU5LCJ2ZXIiOiIxLjAiLCJ0aWQiOiI2OTJhZGVjZi1lY2ZiLTQ0ZmUtOWEyMi03YzdmMjQzMDYwMDIiLCJvaWQiOiI0Njc0YWRiMS1mNTU4LTQ4MmUtOGM4MC04NmQzMjBmZWUwNDgiLCJ1cG4iOiJhZG1pbkBjb252ZXJnZVRlc3Qub25taWNyb3NvZnQuY29tIiwicHVpZCI6IjEwMDMzRkZGOTBFREU5NzEiLCJzdWIiOiJnbGp6V3BEZHJfT3ZPV2M1dXdQckt3MkZmdXBadU1PVjcyZFlDQU5SVGRBIiwiZ2l2ZW5fbmFtZSI6ImFkbWluIiwiZmFtaWx5X25hbWUiOiJhZG1pbiIsIm5hbWUiOiJhZG1pbiBhZG1pbiIsImFtciI6WyJwd2QiXSwidW5pcXVlX25hbWUiOiJhZG1pbkBjb252ZXJnZVRlc3Qub25taWNyb3NvZnQuY29tIiwiYXBwaWQiOiJlMWViOGE4ZC03YjBjLTRhMTQtOTMxMy0zZjJjMjVjODI5MjkiLCJhcHBpZGFjciI6IjEiLCJzY3AiOiJNYWlsLlJlYWQiLCJhY3IiOiIxIn0.o0vNXLXrHQs4Mu2tjkjtngoTccHjDAS3mFZe3YloNpbr_pQKPk784vBB-CBerwm3Asc5P4hnJ_lsGhE67s70h0bQQc08Fa9hDjTutl8mtC8SnzR3lhr_4rE1zl8_wIQGmdX6jir9vdrOziOLBXSUms_PwgkgTekRcRD6sXnO4ES40InoQBN94ANm-xc4jMTn2hD_4hIywu8Pil7eFtZ26HHRJdIR8DF0HliEXZ3AgNUpLmPGvZKFmJ6c6JmL-XTtxF-Nnp_VSa6tod0P6DuXTMWnnqlFIaRsAiBCo2IBfLfkW9LbcNIeEQb42Km7x-PymBrZRtrVTjH4CqJ3qNPGcw\",\"refresh_token\":\"OAAABAAAAiL9Kn2Z27UubvWFPbm0gLam8oo7uhd6_0TnCKEplswX89HQhihggWEstgFcorro3BpegqIolvZQ4TpxuIX_6ZKJmCtdWO90Kvn87iF13wrQnYpHEr3mNBi9CdV8jej_i88x2KXz8gGV2FdyWA5QBhc-rJhe8CCmh1GRF26JUgZXraEOsLtXLJKxPzrjWM0lNUKbXnqLZWumKAlc3euZrCGXDwrLV73rn7r_LKef2_V-toWAzceNHhqzyOfxmjeffsZ5pmh8ZR9JdOZ3C-tbMSBETJuqHlNz3tVgPu-gC4wTgNA3Cm7OFvM3ni2jzxzcBJ6h7H6nsU0KgP7EMHPW1I1wqTpqSIz439hx3IzQ3jx9vcMJk3YqxSkbiqlfju6l0qwB-mzvo4h_6UOGVS9a81ZJ_BqQ-JUrkCzdXr8wpqkOitNjNc2MvMuFIubeGs4zVaO9WbYEIFDnVb70XgdHZTU0faVu80XsUAJnjYis6e3fe2F2pIKAPQZj1aq9yJWt27pgRNE8WoRA7gGdhuDFLZk4K_o4h7hmAYvICVsQPLJ-KI3uTFCuugc9ZiG0H_TLlAVaikJowb1Stj4_FVG6npqZLACHXpFqf5SPqoY8nB38uwC0TO1Vun2fv6QHp23kB4G0q4G8oJrMZmA_IcRx0RSCFRj2g-9B7IDV78eHBcMPYN1XeG41KiYjjLBViwN0iVCmoKNL0Wxt39KrS2cI1ZzHsnxPdAOpKpwVLgoLUAiM1aywhellEXAvY1x7tr4Ks_QTXghPR4TLRBRU6Z9a9xhL6WFmyIYwwflklCyesYXPoHTU_tPJcRPuhnV7MoNLnkOTJ7WiMfXnyJpcS7oWZVJQkjTl24REB49oQPgezZ7cNWB7lSffO5Rd2p0BzqoIA5SWgLf2ENJ--cV6zf16L0iAA\",\"id_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJlMWViOGE4ZC03YjBjLTRhMTQtOTMxMy0zZjJjMjVjODI5MjkiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNjkyYWRlY2YtZWNmYi00NGZlLTlhMjItN2M3ZjI0MzA2MDAyL3YyLjAvIiwiaWF0IjoxNDM0MTMxMjU5LCJuYmYiOjE0MzQxMzEyNTksImV4cCI6MTQzNDEzNTE1OSwidmVyIjoiMi4wIiwidGlkIjoiNjkyYWRlY2YtZWNmYi00NGZlLTlhMjItN2M3ZjI0MzA2MDAyIiwib2lkIjoiNDY3NGFkYjEtZjU1OC00ODJlLThjODAtODZkMzIwZmVlMDQ4IiwiZW1haWwiOiJhZG1pbkBjb252ZXJnZVRlc3Qub25taWNyb3NvZnQuY29tIiwic3ViIjoiaU5CaDVnSE1XRXdKdGZKTVBsbHpwMU1JbXNHMWRFa3pYZWliZ1BVdC16OCIsIm5hbWUiOiJhZG1pbiBhZG1pbiIsImF1dGhfdGltZSI6MTQzNDEzMDg5M30.OxBoUrMQIBn9dZ3F8PfXoSMpr718KOeD2vHvA9MnP8NWgrugK3n_gYXVRR7IiuTjiYf08NVdG-cvTXOr1fvg78zAhEiBRmnGZWGfW8VSzKd5D1ZqHyMRL8jQPHbN8Tok8parbfjEYHrPrqxMyiGJ5oGcDsB1fyjsLghGOagvbK1B8SCo_yICvw0hicjSsiLitYFnul27RVvXxp7B-ZhRZGfTyH8orDpcHXoxcVb_QoVozd06XsQEXzXXS_WyhZAHSr4eSKj0IA52ghF9f46ZHqHBUeGtLzjNrjgzuUUehD6fHkTJUb-XuUGyGYX-7_c-CeyEjHa_rz0LeLUkjbhhDA\"}")
                )
            {
                webResponse.ResponseStream.Returns(stream);
                response = TokenResponse.CreateFromErrorResponse(webResponse);
                Assert.IsNotNull(response);
            }
            
            using (
                var stream =
                    MockHelpers.GenerateStreamFromString(
                        "random-string")
                )
            {
                webResponse.ResponseStream.Returns(stream);
                response = TokenResponse.CreateFromErrorResponse(webResponse);
                Assert.IsNotNull(response);
                Assert.AreEqual(response.Error, MsalError.Unknown);
                Assert.AreEqual(response.ErrorDescription, "random-string");
            }

            using (
                var stream =
                    MockHelpers.GenerateStreamFromString(
                        "random-string")
                )
            {
                webResponse.ResponseStream.Returns(stream);
                webResponse.StatusCode.Returns(HttpStatusCode.ServiceUnavailable);
                response = TokenResponse.CreateFromErrorResponse(webResponse);
                Assert.IsNotNull(response);
                Assert.AreEqual(response.Error, MsalError.ServiceUnavailable);
                Assert.AreEqual(response.ErrorDescription, "random-string");
            }
        }

        [TestMethod]
        [TestCategory("TokenResponseTests")]
        public void GetResultTest()
        {
            TokenResponse response = new TokenResponse();
            response.IdTokenString =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiI3YzdhMmY3MC1jYWVmLTQ1YzgtOWE2Yy0wOTE2MzM1MDFkZTQiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vODE2OTAyODYtNTA1NC00Zjk3LWI3MDgtNTQxNjU0Y2Q5MjFhL3YyLjAvIiwiaWF0IjoxNDU1NTc2MjM1LCJuYmYiOjE0NTU1NzYyMzUsImV4cCI6MTQ1NTU4MDEzNSwibmFtZSI6IkFEQUwgT2JqLUMgLSBFMkUiLCJvaWQiOiIxZTcwYThlZi1jYjIwLTQxOWMtYjhhNy1hNDJlZDJmYTIyNzciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJlMmVAYWRhbG9iamMub25taWNyb3NvZnQuY29tIiwic3ViIjoibHJxVDlsQXQzSUlhS3hHanE2UlNReFRqN3diV3Q2RnpaMFU3NkJZMEJINCIsInRpZCI6IjgxNjkwMjg2LTUwNTQtNGY5Ny1iNzA4LTU0MTY1NGNkOTIxYSIsInZlciI6IjIuMCJ9.axS_-N3Z3b1GnZftxb6dKtMeooldoIQ_B7YrVO4CQI9xhHI1_Vl-dXfsFHBPRvIvXBEfBEehaaWq9B9P_CD5TpQXGycsYS08knHf_QpHIJ9WQbBIJ774divakx7kN6x7IxjoD1PrfRfo2QZsLLAz-1n-NHt7FwtkBQpKTDfgc6cVShy9isaJt5WoxfUM1eNo1HK_YjHj7Q5-n-XiZEbe-8m-7nqwBw86QDlLdk7dBhhCzVzXZb_5HCHI-23xZLYR34RoW7ljYEG4P8auEcML1haS4MN83VKRorMyljAIoA4YOgbfnvnlAlxRz_rtAAcjNqaUpIwzadGzd-QVbyoKPQ";
            response.AccessToken = "access-token";
            response.ExpiresIn = 3599;
            response.CorrelationId = "correlation-id";
            response.RefreshToken = "refresh-token";
            response.FamilyId = "1";
            response.Scope = "scope1 scope2";
            response.TokenType = "Bearer";

            AuthenticationResultEx resultEx = response.GetResult();
            Assert.IsNotNull(resultEx);
            Assert.AreEqual("access-token", resultEx.Result.AccessToken);
            Assert.AreEqual("scope1 scope2", resultEx.Result.ScopeSet.AsSingleString());
            Assert.AreEqual("Bearer", resultEx.Result.AccessTokenType);
        }
        
        private static TokenResponse CreateTokenResponse()
        {
            return new TokenResponse
            {
                AccessToken = "access_token",
                RefreshToken = "refresh_token",
                CorrelationId = Guid.NewGuid().ToString(),
                Scope = "my-resource",
                TokenType = "Bearer",
                ExpiresIn = 3899
            };
        }
    }
}
