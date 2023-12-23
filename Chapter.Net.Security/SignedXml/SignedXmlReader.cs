// -----------------------------------------------------------------------------------------------------------------
// <copyright file="SignedXmlReader.cs" company="my-libraries">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;

// Code source: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security;

/// <inheritdoc />
public class SignedXmlReader : ISignedXmlReader
{
    private readonly SignedXmlOptions _options;

    /// <summary>
    ///     Creates a new instance of the SignedXmlReader.
    /// </summary>
    /// <param name="options">The options.</param>
    public SignedXmlReader(SignedXmlOptions options)
    {
        _options = options;
    }

    /// <inheritdoc />
    public bool Verify(XmlDocument doc)
    {
        if (_options.Algo == null)
            throw new InvalidOperationException("The SignedXmlOptions.Algo must be set.");

        var signedXml = new SignedXml(doc);
        var nodeList = doc.GetElementsByTagName("Signature");
        signedXml.LoadXml((XmlElement)nodeList[0]!);
        return signedXml.CheckSignature(_options.Algo);
    }

    /// <inheritdoc />
    public bool VerifyXml(string xml)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        return Verify(doc);
    }

    /// <inheritdoc />
    public bool VerifyFile(string sourceFilePath)
    {
        var doc = new XmlDocument();
        doc.Load(sourceFilePath);
        return Verify(doc);
    }

    /// <inheritdoc />
    public bool Read<TObject>(XmlDocument doc, out TObject document)
    {
        var isValid = Verify(doc);
        if (_options.AllowReadInvalid || isValid)
        {
            var xmlSerializer = new XmlSerializer(typeof(TObject));
            using var reader = new XmlNodeReader(doc);
            document = (TObject)xmlSerializer.Deserialize(reader)!;
        }
        else
        {
            document = default!;
        }

        return isValid;
    }

    /// <inheritdoc />
    public bool ReadXml<TObject>(string xml, out TObject document)
    {
        var isValid = VerifyXml(xml);
        if (_options.AllowReadInvalid || isValid)
        {
            var xmlSerializer = new XmlSerializer(typeof(TObject));
            using var reader = new StringReader(xml);
            document = (TObject)xmlSerializer.Deserialize(reader)!;
        }
        else
        {
            document = default!;
        }

        return isValid;
    }

    /// <inheritdoc />
    public bool ReadFile<TObject>(string sourceFilePath, out TObject document)
    {
        var isValid = VerifyFile(sourceFilePath);
        if (_options.AllowReadInvalid || isValid)
        {
            var xmlSerializer = new XmlSerializer(typeof(TObject));
            using var reader = new FileStream(sourceFilePath, FileMode.Open);
            document = (TObject)xmlSerializer.Deserialize(reader)!;
        }
        else
        {
            document = default!;
        }

        return isValid;
    }
}