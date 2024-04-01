// -----------------------------------------------------------------------------------------------------------------
// <copyright file="ISignedXmlWriter.cs" company="my-libraries">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

#if !NET5_0 && !NET45
using System.Xml;

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security
{
    /// <summary>
    ///     Provides methods to store xml data with signing.
    /// </summary>
    public interface ISignedXmlWriter
    {
        /// <summary>
        ///     Signs the given object.
        /// </summary>
        /// <typeparam name="TObject">The type of the object to sign.</typeparam>
        /// <param name="document">The data to sign.</param>
        /// <returns>The signed xml document.</returns>
        XmlDocument Sign<TObject>(TObject document);

        /// <summary>
        ///     Signs the given xml document.
        /// </summary>
        /// <param name="document">The xml document to sign.</param>
        void Sign(XmlDocument document);

        /// <summary>
        ///     Signs the given xml string.
        /// </summary>
        /// <param name="xml">The xml string to sign.</param>
        /// <returns>The signed xml document.</returns>
        XmlDocument SignXml(string xml);

        /// <summary>
        ///     Signs the given xml file.
        /// </summary>
        /// <param name="sourceFilePath">The xml file to sign.</param>
        /// <returns>The signed xml document.</returns>
        XmlDocument SignFile(string sourceFilePath);

        /// <summary>
        ///     Signs and writes the given object to a file.
        /// </summary>
        /// <typeparam name="TObject">The type of the object to sign and write.</typeparam>
        /// <param name="document">The data to sign and write.</param>
        /// <param name="targetFilePath">The target file path.</param>
        void Write<TObject>(TObject document, string targetFilePath);

        /// <summary>
        ///     Signs and writes the given xml document to a file.
        /// </summary>
        /// <param name="doc">The xml document to sign and write.</param>
        /// <param name="targetFilePath">The target file path.</param>
        void Write(XmlDocument doc, string targetFilePath);

        /// <summary>
        ///     Signs and writes the given xml string to a file.
        /// </summary>
        /// <param name="xml">The xml string to sign and write.</param>
        /// <param name="targetFilePath">The target file path.</param>
        void WriteXml(string xml, string targetFilePath);

        /// <summary>
        ///     Signs and writes the given xml file to a file.
        /// </summary>
        /// <param name="sourceFilePath">The xml file to sign and write.</param>
        /// <param name="targetFilePath">The target file path.</param>
        void WriteFile(string sourceFilePath, string targetFilePath);
    }
}
#endif