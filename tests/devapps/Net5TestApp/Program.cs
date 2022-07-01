﻿using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Test.LabInfrastructure;

namespace Net5TestApp
{
    class Program
    {
        private const string clientIdCCA = "16dab2ba-145d-4b1b-8569-bf4b9aed4dc8";
        private const string thumbprint = "4E87313FD450985A10BC0F14A292859F2DCD6CD3";
        private static readonly string authorityA = $"https://login.microsoftonline.com/organizations";
        private const string scopeGraphDefault = "https://graph.microsoft.com//.default";

        static async Task Main(string[] args)
        {
            try
            {

                var cache = new CompositeCacheAdapter();

                var cca = ConfidentialClientApplicationBuilder
                    .Create(clientIdCCA)
                    .WithAuthority(authorityA)
                    .WithCertificate(CertificateHelper.FindCertificateByThumbprint(thumbprint))
                    .WithCacheOptions(new CacheOptions(identityCache: cache))
                    .WithLogging(MyLoggingMethod, logLevel: LogLevel.Verbose, enablePiiLogging: false)
                    .Build();

                var result1 = await cca
                    .AcquireTokenForClient(new string[] { scopeGraphDefault })
                    .ExecuteAsync()
                    .ConfigureAwait(true);
                Console.WriteLine(result1.AuthenticationResultMetadata.TokenSource + " " + result1.AccessToken.Substring(result1.AccessToken.Length - 11, 10) + Environment.NewLine);

                var result2 = await cca
                    .AcquireTokenForClient(new string[] { scopeGraphDefault })
                    .ExecuteAsync()
                    .ConfigureAwait(true);
                Console.WriteLine(result2.AuthenticationResultMetadata.TokenSource + " " + result2.AccessToken.Substring(result2.AccessToken.Length - 11, 10) + Environment.NewLine);

                Console.ResetColor();
            }
            catch (MsalException e)
            {
                Console.BackgroundColor = ConsoleColor.DarkRed;
                Console.WriteLine("Error: ErrorCode=" + e.ErrorCode + "ErrorMessage=" + e.Message);
                Console.ResetColor();
            }

            Console.Read();
        }

        static void MyLoggingMethod(LogLevel level, string message, bool containsPii)
        {
            Console.WriteLine($"MSALTest {level} {containsPii} {message}");
        }
    }
}
