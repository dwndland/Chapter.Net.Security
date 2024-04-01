// -----------------------------------------------------------------------------------------------------------------
// <copyright file="ISignedXmlReader.cs" company="my-libraries">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

#if !NET5_0 && !NET45
using System.Xml;

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security
{
    /// <summary>
    ///     Provides methods to verify file signatures and read its data.
    /// </summary>
    public interface ISignedXmlReader
    {
        /// <summary>
        ///     Verifies the signature of the given xml document.
        /// </summary>
        /// <param name="doc">The xml document to verify.</param>
        /// <returns>True if the signature is valid; otherwise false.</returns>
        bool Verify(XmlDocument doc);

        /// <summary>
        ///     Verifies the signature of the given xml string.
        /// </summary>
        /// <param name="xml">The xml string to verify.</param>
        /// <returns>True if the signature is valid; otherwise false.</returns>
        bool VerifyXml(string xml);

        /// <summary>
        ///     Verifies the signature of the given xml file.
        /// </summary>
        /// <param name="sourceFilePath">The xml file to verify.</param>
        /// <returns>True if the signature is valid; otherwise false.</returns>
        bool VerifyFile(string sourceFilePath);

        /// <summary>
        ///     Verifies and reads the given xml document into the target object.
        /// </summary>
        /// <typeparam name="TObject">The type of the target object.</typeparam>
        /// <param name="doc">The xml document to verify and read.</param>
        /// <param name="document">The target object.</param>
        /// <returns>True if the signature is valid; otherwise false.</returns>
        bool Read<TObject>(XmlDocument doc, out TObject document);

        /// <summary>
        ///     Verifies and reads the given xml string into the target object.
        /// </summary>
        /// <typeparam name="TObject">The type of the target object.</typeparam>
        /// <param name="xml">The xml string to verify and read.</param>
        /// <param name="document">The target object.</param>
        /// <returns>True if the signature is valid; otherwise false.</returns>
        bool ReadXml<TObject>(string xml, out TObject document);

        /// <summary>
        ///     Verifies and reads the given xml file into the target object.
        /// </summary>
        /// <typeparam name="TObject">The type of the target object.</typeparam>
        /// <param name="sourceFilePath">The xml file to verify and read.</param>
        /// <param name="document">The target object.</param>
        /// <returns>True if the signature is valid; otherwise false.</returns>
        bool ReadFile<TObject>(string sourceFilePath, out TObject document);
    }
}
#endif