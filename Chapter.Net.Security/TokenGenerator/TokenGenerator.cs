// -----------------------------------------------------------------------------------------------------------------
// <copyright file="TokenGenerator.cs" company="my-libraries">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security;

/// <summary>
///     Generates a security token.
/// </summary>
public class TokenGenerator : ITokenGenerator
{
    /// <summary>
    ///     Generates a 32 character long security token as base64.
    /// </summary>
    /// <returns>The generated security token.</returns>
    public string Generate()
    {
        return Generate(32);
    }

    /// <summary>
    ///     Generates a security token with the given length.
    /// </summary>
    /// <param name="length">The length of the security token.</param>
    /// <returns>The generated security token.</returns>
    /// <exception cref="ArgumentException">length cannot be 0.</exception>
    public string Generate(uint length)
    {
        if (length == 0)
            throw new ArgumentException("length cannot be 0.");

        var randomNumber = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}