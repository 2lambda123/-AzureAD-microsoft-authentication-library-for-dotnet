// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ComponentModel;

namespace Microsoft.Identity.Client.Extensibility {
/// <summary>
///
/// </summary>
public static class AcquireTokenForClientBuilderExtensions {

  /// <summary>
  /// Sets the proof of possession key ID for the client and returns the parameter builder.
  /// </summary>
  /// <param name="builder">The parameter builder.</param>
  /// <param name="keyId">The proof of possession key ID.</param>
  /// <param name="expectedTokenTypeFromAad">The expected token type from Azure Active Directory (default is "Bearer").</param>
  /// <exception cref="ArgumentNullException">Thrown when <paramref name="keyId"/> is null or empty.</exception>
  /// <returns>The parameter builder with the proof of possession key ID set.</returns>
  /// <remarks>
  /// This method sets the proof of possession key ID for the client in the parameter builder.
  /// It validates the use of experimental feature and sets the authentication scheme to an external bound token scheme using the provided key ID and expected token type from Azure Active Directory.
  /// </remarks>
  [EditorBrowsable(
      EditorBrowsableState
          .Never)] // https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/issues/4789
  public static AcquireTokenForClientParameterBuilder
  WithProofOfPosessionKeyId(this AcquireTokenForClientParameterBuilder builder,
                            string keyId,
                            string expectedTokenTypeFromAad = "Bearer") {
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
