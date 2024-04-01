// -----------------------------------------------------------------------------------------------------------------
// <copyright file="IHashing.cs" company="my-libraries">
//     Copyright (c) David Wendland. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace

namespace Chapter.Net.Security
{
    /// <summary>
    ///     Provides methods to hash data.
    /// </summary>
    public interface IHashing
    {
        /// <summary>
        ///     Sets the custom hashing algorithm for <see cref="GenerateCustomHash(string)" /> and the other.
        /// </summary>
        /// <param name="factory">The factory priding the hashing algorithm to use for the GenerateCustom methods.</param>
        void SetCustomHashingMethod(Func<HashAlgorithm> factory);

        /// <exception cref="ArgumentNullException">The factory cannot be null.</exception>
        /// <summary>
        ///     Generates a secure hash (SHA256) with a 32 char long salt.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashing data.</returns>
        /// <exception cref="ArgumentNullException">value is null.</exception>
        HashData GenerateSecureHash(string value);

        /// <summary>
        ///     Generates a secure hash (SHA256) with the given salt.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <param name="salt">The salt to use when hashing.</param>
        /// <returns>The hashed value.</returns>
        /// <exception cref="ArgumentNullException">value is null.</exception>
        /// <exception cref="ArgumentNullException">salt is null.</exception>
        string GenerateSecureHash(string value, byte[] salt);

        /// <summary>
        ///     Hashes the value using the SHA256 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        /// <exception cref="ArgumentNullException">value is null.</exception>
        string GenerateSHA256Hash(string value);

        /// <summary>
        ///     Hashes the bytes using the SHA256 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        /// <exception cref="ArgumentNullException">bytes is null.</exception>
        string GenerateSHA256Hash(byte[] bytes);

        /// <summary>
        ///     Hashes the stream content using the SHA256 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        string GenerateSHA256Hash(Stream stream);

        /// <summary>
        ///     Hashes the value using the SHA384 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        /// <exception cref="ArgumentNullException">value is null.</exception>
        string GenerateSHA384Hash(string value);

        /// <summary>
        ///     Hashes the bytes using the SHA384 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        /// <exception cref="ArgumentNullException">bytes is null.</exception>
        string GenerateSHA384Hash(byte[] bytes);

        /// <summary>
        ///     Hashes the stream content using the SHA384 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        string GenerateSHA384Hash(Stream stream);

        /// <summary>
        ///     Hashes the value using the SHA512 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        /// <exception cref="ArgumentNullException">value is null.</exception>
        string GenerateSHA512Hash(string value);

        /// <summary>
        ///     Hashes the bytes using the SHA512 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        /// <exception cref="ArgumentNullException">bytes is null.</exception>
        string GenerateSHA512Hash(byte[] bytes);

        /// <summary>
        ///     Hashes the stream content using the SHA512 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        string GenerateSHA512Hash(Stream stream);

        /// <summary>
        ///     Hashes the value using the MD5 algorithm.
        /// </summary>
        /// <param name="value">The value to hash.</param>
        /// <returns>The hashed value.</returns>
        /// <exception cref="ArgumentNullException">value is null.</exception>
        string GenerateMD5Hash(string value);

        /// <summary>
        ///     Hashes the bytes using the MD5 algorithm.
        /// </summary>
        /// <param name="bytes">The bytes to hash.</param>
        /// <returns>The hashed bytes.</returns>
        /// <exception cref="ArgumentNullException">bytes is null.</exception>
        string GenerateMD5Hash(byte[] bytes);

        /// <summary>
        ///     Hashes the stream content using the MD5 algorithm.
        /// </summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <returns>The hashed stream content data.</returns>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        string GenerateMD5Hash(Stream stream);

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
        string GenerateCustomHash(string value);

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
        string GenerateCustomHash(byte[] bytes);

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
        string GenerateCustomHash(Stream stream);

        /// <summary>
        ///     Generates a salt with the length of 32 characters.
        /// </summary>
        /// <returns>The generated salt.</returns>
        byte[] GenerateSalt();

        /// <summary>
        ///     Generates a salt with the given length.
        /// </summary>
        /// <param name="length">The length of the salt to generate.</param>
        /// <returns>The generated salt.</returns>
        byte[] GenerateSalt(uint length);
    }
}