// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides MD5 hash cryptographic service.
    /// </summary>
    public static class Md5CryptoUtility
    {
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns a substring of the hexadecimal representation.
        /// </summary>
        /// <param name="rawData">The input data to compute hash for.</param>
        /// <param name="toUppercase">Specifies whether to convert hexadecimal characters to uppercase. Default is true.</param>
        /// <returns>A 16-character substring of the hexadecimal representation of the hash (starting from position 8).</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeHashToHexSubstring(byte[] rawData, bool toUppercase = true)
        {
            var hexString = ComputeHashToHexString(rawData, toUppercase);
            return hexString.Substring(8, 16);
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns the hexadecimal representation.
        /// </summary>
        /// <param name="rawData">The input data to compute hash for.</param>
        /// <param name="toUppercase">Specifies whether to convert hexadecimal characters to uppercase. Default is true.</param>
        /// <returns>The hexadecimal string representation of the computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeHashToHexString(byte[] rawData, bool toUppercase = true)
        {
            var hashBytes = ComputeHash(rawData);
            var hexString = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            return toUppercase ? hexString : hexString.ToLower();
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns a Base64-encoded substring of the hash.
        /// </summary>
        /// <param name="rawData">The input data to compute hash for.</param>
        /// <returns>A Base64-encoded string representation of the middle 8 bytes of the hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeHashToBase64Substring(byte[] rawData)
        {
            var hashBytes = ComputeHash(rawData);
            var subHashBytes = new byte[hashBytes.Length / 2];
            Array.Copy(hashBytes, 4, subHashBytes, 0, 8);
            return Convert.ToBase64String(subHashBytes);
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns the Base64-encoded representation.
        /// </summary>
        /// <param name="rawData">The input data to compute hash for.</param>
        /// <returns>A Base64-encoded string representation of the computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeHashToBase64String(byte[] rawData)
        {
            var hashBytes = ComputeHash(rawData);
            return Convert.ToBase64String(hashBytes);
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array.
        /// </summary>
        /// <param name="rawData">The input data to compute hash for.</param>
        /// <returns>The computed MD5 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static byte[] ComputeHash(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            using var md5 = MD5.Create();
            return md5.ComputeHash(rawData);
        }
    }
}