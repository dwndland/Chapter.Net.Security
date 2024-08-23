// -----------------------------------------------------------------------------------------------------------------
// <copyright file="SignedXmlOptions.cs" company="dwndland">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

using System.Security.Cryptography;

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security;

/// <summary>
///     Defines options for the <see cref="SignedXmlReader" /> and <see cref="SignedXmlWriter" />.
/// </summary>
public class SignedXmlOptions
{
    /// <summary>
    ///     Creates a new instance of SignedXmlOptions.
    /// </summary>
    public SignedXmlOptions()
    {
        WriteIndented = true;
        AllowReadInvalid = true;
    }

    /// <summary>
    ///     The algorithm to use for sign the xml file.
    /// </summary>
    public AsymmetricAlgorithm Algo { get; set; }

    /// <summary>
    ///     Defines if the store xml file shall be written indented or not.
    /// </summary>
    public bool WriteIndented { get; set; }

    /// <summary>
    ///     Defines if the read outputs the serialized data in the case the signature is invalid.
    /// </summary>
    public bool AllowReadInvalid { get; set; }
}