// -----------------------------------------------------------------------------------------------------------------
// <copyright file="HashData.cs" company="my-libraries">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security;

/// <summary>
///     Contains a generated hash with the used salt.
/// </summary>
public class HashData
{
    /// <summary>
    ///     Creates a new HashData.
    /// </summary>
    /// <param name="value">The hashed value.</param>
    /// <param name="salt">The salt.</param>
    public HashData(string value, byte[] salt)
    {
        Value = value;
        Salt = salt;
    }

    /// <summary>
    ///     The used salt.
    /// </summary>
    public byte[] Salt { get; set; }

    /// <summary>
    ///     The hash value.
    /// </summary>
    public string Value { get; set; }
}