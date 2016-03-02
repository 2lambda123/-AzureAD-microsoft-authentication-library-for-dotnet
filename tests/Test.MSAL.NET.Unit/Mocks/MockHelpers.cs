﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Test.MSAL.NET.Unit
{
    internal static class MockHelpers
    {
        public static Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public static HttpResponseMessage CreatePositiveTokenResponseMessage()
        {
            HttpResponseMessage responseMessage = new HttpResponseMessage(HttpStatusCode.OK);
            HttpContent content = new StringContent("{\"token_type\":\"Bearer\",\"expires_in\":\"3599\",\"scope\":\"https://outlook.office.com/mail.read\",\"access_token\":\"some-access-token\",\"refresh_token\":\"OAAsomethingencryptedQwgAA\",\"id_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJlODU0YTRhNy02YzM0LTQ0OWMtYjIzNy1mYzdhMjgwOTNkODQiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNmMzZDUxZGQtZjBlNS00OTU5LWI0ZWEtYTgwYzRlMzZmZTVlL3YyLjAvIiwiaWF0IjoxNDU1ODMzODI4LCJuYmYiOjE0NTU4MzM4MjgsImV4cCI6MTQ1NTgzNzcyOCwiaXBhZGRyIjoiMTMxLjEwNy4xNTkuMTE3IiwibmFtZSI6Ik1hcmlvIFJvc3NpIiwib2lkIjoiMTNkMzEwNGEtNjg5MS00NWQyLWE0YmUtODI1ODFhOGU0NjViIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibWFyaW9AZGV2ZWxvcGVydGVuYW50Lm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6Iks0X1NHR3hLcVcxU3hVQW1oZzZDMUY2VlBpRnpjeC1RZDgwZWhJRWRGdXMiLCJ0aWQiOiI2YzNkNTFkZC1mMGU1LTQ5NTktYjRlYS1hODBjNGUzNmZlNWUiLCJ2ZXIiOiIyLjAifQ.Z6Xc_PzqTtB-2TjyZwPpFGgkAs47m95F_I-NHxtIJT-H20i_1kbcBdmJaj7lMjHhJwAAMM-tE-iBVF9f7jNmsDZAADt-HgtrrXaXxkIKMwQ_MuB-OI4uY9KYIurEqmkGvOlRUK1ZVNNf7IKE5pqNTOZzyFDEyG8SwSvAmN-J4VnrxFz3d47klHoKVKwLjWJDj7edR2UUkdUQ6ZRj7YBj9UjC8UrmVNLBmvyatPyu9KQxyNyJpmTBT2jDjMZ3J1Z5iL98zWw_Ez0-6W0ti87UaPreJO3hejqQE_pRa4rXMLpw3oAnyEE1H7n0F6tK_3lJndZi9uLTIsdSMEXVnZdoHg\",\"id_token_expires_in\":\"3600\",\"profile_info\":\"eyJ2ZXIiOiIxLjAiLCJuYW1lIjoiTWFyaW8gUm9zc2kiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJtYXJpb0BkZXZlbG9wZXJ0ZW5hbnQub25taWNyb3NvZnQuY29tIiwic3ViIjoiSzRfU0dHeEtxVzFTeFVBbWhnNkMxRjZWUGlGemN4LVFkODBlaElFZEZ1cyIsInRpZCI6IjZjM2Q1MWRkLWYwZTUtNDk1OS1iNGVhLWE4MGM0ZTM2ZmU1ZSJ9\"}");
            responseMessage.Content = content;
            return responseMessage;
        }
    }
}
