// -----------------------------------------------------------------------------------------------------------------
// <copyright file="Hashing.cs" company="my-libraries">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security;

/// <summary>
///     Provides methods to hash data.
/// </summary>
public class Hashing : IHashing
{
    private Func<HashAlgorithm> _factory;

    /// <summary>
    ///     Sets the custom hashing algorithm for <see cref="GenerateCustomHash(string)" /> and the other.
    /// </summary>
    /// <param name="factory">The factory priding the hashing algorithm to use for the GenerateCustom methods.</param>
    /// <exception cref="ArgumentNullException">The factory cannot be null.</exception>
    public void SetCustomHashingMethod(Func<HashAlgorithm> factory)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <summary>
    ///     Generates a secure hash (SHA256) with a 32 char long salt.
    /// </summary>
    /// <param name="value">The value to hash.</param>
    /// <returns>The hashing data.</returns>
    /// <exception cref="ArgumentNullException">value is null.</exception>
    public HashData GenerateSecureHash(string value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));

        var salt = GenerateSalt();
        var hashedValue = GenerateSHA256Hash(value + Convert.ToBase64String(salt));
        return new HashData(hashedValue, salt);
    }

    /// <summary>
    ///     Generates a secure hash (SHA256) with the given salt.
    /// </summary>
    /// <param name="value">The value to hash.</param>
    /// <param name="salt">The salt to use when hashing.</param>
    /// <returns>The hashed value.</returns>
    /// <exception cref="ArgumentNullException">value is null.</exception>
    /// <exception cref="ArgumentNullException">salt is null.</exception>
    public string GenerateSecureHash(string value, byte[] salt)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));
        if (salt == null)
            throw new ArgumentNullException(nameof(salt));

        return GenerateSHA256Hash(value + Convert.ToBase64String(salt));
    }

    /// <summary>
    ///     Hashes the value using the SHA256 algorithm.
    /// </summary>
    /// <param name="value">The value to hash.</param>
    /// <returns>The hashed value.</returns>
    /// <exception cref="ArgumentNullException">value is null.</exception>
    public string GenerateSHA256Hash(string value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));

        return GenerateSHA256Hash(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    ///     Hashes the bytes using the SHA256 algorithm.
    /// </summary>
    /// <param name="bytes">The bytes to hash.</param>
    /// <returns>The hashed bytes.</returns>
    /// <exception cref="ArgumentNullException">bytes is null.</exception>
    public string GenerateSHA256Hash(byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        return GenerateCustomHash(SHA256.Create(), bytes);
    }

    /// <summary>
    ///     Hashes the stream content using the SHA256 algorithm.
    /// </summary>
    /// <param name="stream">The stream with the data to hash.</param>
    /// <returns>The hashed stream content data.</returns>
    /// <exception cref="ArgumentNullException">stream is null.</exception>
    public string GenerateSHA256Hash(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        return GenerateCustomHash(SHA256.Create(), stream);
    }

    /// <summary>
    ///     Hashes the value using the SHA384 algorithm.
    /// </summary>
    /// <param name="value">The value to hash.</param>
    /// <returns>The hashed value.</returns>
    /// <exception cref="ArgumentNullException">value is null.</exception>
    public string GenerateSHA384Hash(string value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));

        return GenerateSHA384Hash(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    ///     Hashes the bytes using the SHA384 algorithm.
    /// </summary>
    /// <param name="bytes">The bytes to hash.</param>
    /// <returns>The hashed bytes.</returns>
    /// <exception cref="ArgumentNullException">bytes is null.</exception>
    public string GenerateSHA384Hash(byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        return GenerateCustomHash(SHA384.Create(), bytes);
    }

    /// <summary>
    ///     Hashes the stream content using the SHA384 algorithm.
    /// </summary>
    /// <param name="stream">The stream with the data to hash.</param>
    /// <returns>The hashed stream content data.</returns>
    /// <exception cref="ArgumentNullException">stream is null.</exception>
    public string GenerateSHA384Hash(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        return GenerateCustomHash(SHA384.Create(), stream);
    }

    /// <summary>
    ///     Hashes the value using the SHA512 algorithm.
    /// </summary>
    /// <param name="value">The value to hash.</param>
    /// <returns>The hashed value.</returns>
    /// <exception cref="ArgumentNullException">value is null.</exception>
    public string GenerateSHA512Hash(string value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));

        return GenerateSHA512Hash(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    ///     Hashes the bytes using the SHA512 algorithm.
    /// </summary>
    /// <param name="bytes">The bytes to hash.</param>
    /// <returns>The hashed bytes.</returns>
    /// <exception cref="ArgumentNullException">bytes is null.</exception>
    public string GenerateSHA512Hash(byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        return GenerateCustomHash(SHA512.Create(), bytes);
    }

    /// <summary>
    ///     Hashes the stream content using the SHA512 algorithm.
    /// </summary>
    /// <param name="stream">The stream with the data to hash.</param>
    /// <returns>The hashed stream content data.</returns>
    /// <exception cref="ArgumentNullException">stream is null.</exception>
    public string GenerateSHA512Hash(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        return GenerateCustomHash(SHA512.Create(), stream);
    }

    /// <summary>
    ///     Hashes the value using the MD5 algorithm.
    /// </summary>
    /// <param name="value">The value to hash.</param>
    /// <returns>The hashed value.</returns>
    /// <exception cref="ArgumentNullException">value is null.</exception>
    public string GenerateMD5Hash(string value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));

        return GenerateMD5Hash(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    ///     Hashes the bytes using the MD5 algorithm.
    /// </summary>
    /// <param name="bytes">The bytes to hash.</param>
    /// <returns>The hashed bytes.</returns>
    /// <exception cref="ArgumentNullException">bytes is null.</exception>
    public string GenerateMD5Hash(byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        return GenerateCustomHash(MD5.Create(), bytes);
    }

    /// <summary>
    ///     Hashes the stream content using the MD5 algorithm.
    /// </summary>
    /// <param name="stream">The stream with the data to hash.</param>
    /// <returns>The hashed stream content data.</returns>
    /// <exception cref="ArgumentNullException">stream is null.</exception>
    public string GenerateMD5Hash(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        return GenerateCustomHash(MD5.Create(), stream);
    }

    /// <summary>
    ///     Hashes the value using the algorithm provided by <see cref="SetCustomHashingMethod" />.
    /// </summary>
    /// <param name="value">The value to hash.</param>
    /// <returns>The hashed value.</returns>
    /// <exception cref="NullReferenceException">
    ///     The custom hash algorithm is not set. <see cref="SetCustomHashingMethod" />
    ///     needs to be called first.
    /// </exception>
    /// <exception cref="NullReferenceException">The factory set by <see cref="SetCustomHashingMethod" /> returns null.</exception>
    /// <exception cref="ArgumentNullException">value is null.</exception>
    public string GenerateCustomHash(string value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));

        return GenerateCustomHash(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    ///     Hashes the bytes using the algorithm provided by <see cref="SetCustomHashingMethod" />.
    /// </summary>
    /// <param name="bytes">The bytes to hash.</param>
    /// <returns>The hashed bytes.</returns>
    /// <exception cref="NullReferenceException">
    ///     The custom hash algorithm is not set. <see cref="SetCustomHashingMethod" />
    ///     needs to be called first.
    /// </exception>
    /// <exception cref="NullReferenceException">The factory set by <see cref="SetCustomHashingMethod" /> returns null.</exception>
    /// <exception cref="ArgumentNullException">bytes is null.</exception>
    public string GenerateCustomHash(byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        if (_factory == null)
            throw new NullReferenceException("The custom hash algorithm is not set. SetCustomHashingMethod needs to be called first.");

        var algorithm = _factory();
        if (algorithm == null)
            throw new NullReferenceException("The factory set by SetCustomHashingMethod returns null.");

        return GenerateCustomHash(algorithm, bytes);
    }

    /// <summary>
    ///     Hashes the stream content using the algorithm provided by <see cref="SetCustomHashingMethod" />.
    /// </summary>
    /// <param name="stream">The stream with the data to hash.</param>
    /// <returns>The hashed stream content data.</returns>
    /// <exception cref="NullReferenceException">
    ///     The custom hash algorithm is not set. <see cref="SetCustomHashingMethod" />
    ///     needs to be called first.
    /// </exception>
    /// <exception cref="NullReferenceException">The factory set by <see cref="SetCustomHashingMethod" /> returns null.</exception>
    /// <exception cref="ArgumentNullException">stream is null.</exception>
    public string GenerateCustomHash(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        if (_factory == null)
            throw new NullReferenceException("The custom hash algorithm is not set. SetCustomHashingMethod needs to be called first.");

        var algorithm = _factory();
        if (algorithm == null)
            throw new NullReferenceException("The factory set by SetCustomHashingMethod returns null.");

        return GenerateCustomHash(algorithm, stream);
    }

    /// <summary>
    ///     Generates a salt with the length of 32 characters.
    /// </summary>
    /// <returns>The generated salt.</returns>
    public byte[] GenerateSalt()
    {
        return GenerateSalt(32);
    }

    /// <summary>
    ///     Generates a salt with the given length.
    /// </summary>
    /// <param name="length">The length of the salt to generate.</param>
    /// <returns>The generated salt.</returns>
    public byte[] GenerateSalt(uint length)
    {
        var salt = new byte[length];
        using var random = RandomNumberGenerator.Create();
        random.GetNonZeroBytes(salt);
        return salt;
    }

    private string GenerateCustomHash(HashAlgorithm algorithm, byte[] bytes)
    {
        var hash = algorithm.ComputeHash(bytes);
        return HexHash(hash);
    }

    private string GenerateCustomHash(HashAlgorithm algorithm, Stream stream)
    {
        stream.Position = 0;
        var hash = algorithm.ComputeHash(stream);
        return HexHash(hash);
    }

    private string HexHash(IEnumerable<byte> hash)
    {
        var sb = new StringBuilder();
        foreach (var character in hash)
            sb.Append(character.ToString("X2"));

        return sb.ToString();
    }
}