// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.Extensibility {

/// <summary>
/// Extensions for all AcquireToken methods
/// </summary>
public static class
    AbstractConfidentialClientAcquireTokenParameterBuilderExtension {

  /// <summary>
  /// Sets a handler to be called before a token request is made.
  /// </summary>
  /// <typeparam name="T">The type of the token parameter builder.</typeparam>
  /// <param name="builder">The token parameter builder.</param>
  /// <param name="onBeforeTokenRequestHandler">The asynchronous function to be called before a token request is made.</param>
  /// <returns>The token parameter builder with the onBeforeTokenRequestHandler set.</returns>
  public static AbstractAcquireTokenParameterBuilder<T> OnBeforeTokenRequest<T>(
      this AbstractAcquireTokenParameterBuilder<T> builder,
      Func<OnBeforeTokenRequestData, Task> onBeforeTokenRequestHandler)
      where T : AbstractAcquireTokenParameterBuilder<T> {
    builder.CommonParameters.OnBeforeTokenRequestHandler =
        onBeforeTokenRequestHandler;

    return builder;
  }

  /// <summary>
  /// Adds a proof of possession key identifier to the authentication parameters and returns the modified builder.
  /// </summary>
  /// <typeparam name="T">The type of the builder.</typeparam>
  /// <param name="builder">The original builder to be modified.</param>
  /// <param name="keyId">The proof of possession key identifier to be added.</param>
  /// <param name="expectedTokenTypeFromAad">The expected token type from Azure Active Directory (default is "Bearer").</param>
  /// <returns>The modified builder with the added proof of possession key identifier.</returns>
  /// <exception cref="ArgumentNullException">Thrown when <paramref name="keyId"/> is null or empty.</exception>
  /// <remarks>
  /// This method adds a proof of possession key identifier to the authentication parameters of the builder.
  /// It also sets the authentication scheme to an external bound token scheme using the provided key identifier and expected token type from Azure Active Directory.
  /// </remarks>
  public static AbstractAcquireTokenParameterBuilder<T>
  WithProofOfPosessionKeyId<T>(
      this AbstractAcquireTokenParameterBuilder<T> builder, string keyId,
      string expectedTokenTypeFromAad = "Bearer")
      where T : AbstractAcquireTokenParameterBuilder<T> {
    if (string.IsNullOrEmpty(keyId)) {
      throw new ArgumentNullException(nameof(keyId));
    }

    builder.ValidateUseOfExperimentalFeature();
    builder.CommonParameters.AuthenticationScheme =
        new ExternalBoundTokenScheme(keyId, expectedTokenTypeFromAad);

    return builder;
  }
}
}
