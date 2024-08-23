// -----------------------------------------------------------------------------------------------------------------
// <copyright file="SignedXmlWriter.cs" company="dwndland">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

// Code source: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security;

/// <inheritdoc />
public class SignedXmlWriter : ISignedXmlWriter
{
    private readonly SignedXmlOptions _options;

    /// <summary>
    ///     Creates a new instance of the SignedXmlWriter.
    /// </summary>
    /// <param name="options">The options.</param>
    public SignedXmlWriter(SignedXmlOptions options)
    {
        _options = options;
    }

    /// <inheritdoc />
    public XmlDocument Sign<TObject>(TObject document)
    {
        var xml = SerializeObjectToXmlString(document);
        return SignXmlToXmlDocument(xml);
    }

    /// <inheritdoc />
    public void Sign(XmlDocument document)
    {
        SignXmlDocument(document);
    }

    /// <inheritdoc />
    public XmlDocument SignXml(string xml)
    {
        if (xml == null)
            throw new ArgumentNullException(nameof(xml));

        return SignXmlToXmlDocument(xml);
    }

    /// <inheritdoc />
    public XmlDocument SignFile(string sourceFilePath)
    {
        return SignFileToXmlDocument(sourceFilePath);
    }

    /// <inheritdoc />
    public void Write<TObject>(TObject document, string targetFilePath)
    {
        var xml = SerializeObjectToXmlString(document);
        var doc = SignXmlToXmlDocument(xml);
        WriteXmlFile(doc, targetFilePath);
    }

    /// <inheritdoc />
    public void Write(XmlDocument doc, string targetFilePath)
    {
        SignXmlDocument(doc);
        WriteXmlFile(doc, targetFilePath);
        RemoveSignature(doc);
    }

    /// <inheritdoc />
    public void WriteXml(string xml, string targetFilePath)
    {
        var doc = SignXmlToXmlDocument(xml);
        WriteXmlFile(doc, targetFilePath);
    }

    /// <inheritdoc />
    public void WriteFile(string sourceFilePath, string targetFilePath)
    {
        var doc = SignFileToXmlDocument(sourceFilePath);
        WriteXmlFile(doc, targetFilePath);
    }

    private string SerializeObjectToXmlString<TObject>(TObject toSerialize)
    {
        var xmlSerializer = new XmlSerializer(typeof(TObject));
        using var textWriter = new StringWriter();
        xmlSerializer.Serialize(textWriter, toSerialize);
        return textWriter.ToString();
    }

    private XmlDocument SignXmlToXmlDocument(string xml)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        SignXmlDocument(doc);
        return doc;
    }

    private XmlDocument SignFileToXmlDocument(string filePath)
    {
        var doc = new XmlDocument();
        doc.Load(filePath);
        SignXmlDocument(doc);
        return doc;
    }

    private void RemoveSignature(XmlDocument doc)
    {
        var nodes = doc.GetElementsByTagName("Signature");
        doc.DocumentElement!.RemoveChild(nodes[0]!);
    }

    private void SignXmlDocument(XmlDocument doc)
    {
        var signedXml = new SignedXml(doc)
        {
            SigningKey = _options.Algo
        };
        var signature = signedXml.Signature;
        var reference = new Reference(string.Empty);
        var env = new XmlDsigEnvelopedSignatureTransform();
        reference.AddTransform(env);
        signature.SignedInfo!.AddReference(reference);
        signedXml.ComputeSignature();
        var xmlDigitalSignature = signedXml.GetXml();
        doc.DocumentElement!.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
        if (doc.FirstChild is XmlDeclaration)
            doc.RemoveChild(doc.FirstChild);
    }

    private void WriteXmlFile(XmlDocument doc, string targetFilePath)
    {
        using var xmlTextWriter = new XmlTextWriter(targetFilePath, new UTF8Encoding(true));
        xmlTextWriter.Formatting = _options.WriteIndented ? Formatting.Indented : Formatting.None;
        doc.WriteTo(xmlTextWriter);
    }
}