// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides MD5 hash cryptographic service.
    /// </summary>
    public static class Md5CryptoUtility
    {
        /// <summary>
        /// Computes the MD5 hash of the specified string and returns a substring of the hexadecimal representation.
        /// </summary>
        /// <param name="plainText">The input string to compute hash for.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if null.</param>
        /// <param name="toUppercase">Specifies whether to convert hexadecimal characters to uppercase. Default is true.</param>
        /// <returns>A 16-character substring of the hexadecimal representation of the hash (starting from position 8).</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeHashToHexSubstring(string plainText, Encoding? encoding = null, bool toUppercase = true)
        { 
            var hexString = ComputeHashToHexString(plainText, encoding, toUppercase);
            return hexString.Substring(8, 16);
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns a substring of the hexadecimal representation.
        /// </summary>
        /// <param name="plainData">The input data to compute hash for.</param>
        /// <param name="toUppercase">Specifies whether to convert hexadecimal characters to uppercase. Default is true.</param>
        /// <returns>A 16-character substring of the hexadecimal representation of the hash (starting from position 8).</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeHashToHexSubstring(byte[] plainData, bool toUppercase = true)
        {
            var hexString = ComputeHashToHexString(plainData, toUppercase);
            return hexString.Substring(8, 16);
        }

        /// <summary>
        /// Computes the MD5 hash of the specified string and returns the hexadecimal representation.
        /// </summary>
        /// <param name="plainText">The input string to compute hash for.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if null.</param>
        /// <param name="toUppercase">Specifies whether to convert hexadecimal characters to uppercase. Default is true.</param>
        /// <returns>The hexadecimal string representation of the computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeHashToHexString(string plainText, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHash(plainText, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns the hexadecimal representation.
        /// </summary>
        /// <param name="plainData">The input data to compute hash for.</param>
        /// <param name="toUppercase">Specifies whether to convert hexadecimal characters to uppercase. Default is true.</param>
        /// <returns>The hexadecimal string representation of the computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeHashToHexString(byte[] plainData, bool toUppercase = true)
        {
            var hashCode = ComputeHash(plainData);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the MD5 hash of the specified string and returns a Base64-encoded substring of the hash.
        /// </summary>
        /// <param name="plainText">The input string to compute hash for.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if null.</param>
        /// <returns>A Base64-encoded string representation of the middle 8 bytes of the hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeHashToBase64Substring(string plainText, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            var hashCode = ComputeHash(plainText, encoding);
            var subHashCode = new byte[hashCode.Length / 2];
            Array.Copy(hashCode, 4, subHashCode, 0, 8);
            return Convert.ToBase64String(subHashCode);
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns a Base64-encoded substring of the hash.
        /// </summary>
        /// <param name="plainData">The input data to compute hash for.</param>
        /// <returns>A Base64-encoded string representation of the middle 8 bytes of the hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeHashToBase64Substring(byte[] plainData)
        {
            var hashCode = ComputeHash(plainData);
            var subHashCode = new byte[hashCode.Length / 2];
            Array.Copy(hashCode, 4, subHashCode, 0, 8);
            return Convert.ToBase64String(subHashCode);
        }

        /// <summary>
        /// Computes the MD5 hash of the specified string and returns the Base64-encoded representation.
        /// </summary>
        /// <param name="plainText">The input string to compute hash for.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if null.</param>
        /// <returns>A Base64-encoded string representation of the computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeHashToBase64String(string plainText, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            var hashCode = ComputeHash(plainText, encoding);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array and returns the Base64-encoded representation.
        /// </summary>
        /// <param name="plainData">The input data to compute hash for.</param>
        /// <returns>A Base64-encoded string representation of the computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeHashToBase64String(byte[] plainData)
        {
            var hashCode = ComputeHash(plainData);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the MD5 hash of the specified string.
        /// </summary>
        /// <param name="plainText">The input string to compute hash for.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if null.</param>
        /// <returns>The computed MD5 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static byte[] ComputeHash(string plainText, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            
            encoding ??= Encoding.UTF8;
            return ComputeHash(encoding.GetBytes(plainText));
        }
        
        /// <summary>
        /// Computes the MD5 hash of the specified byte array.
        /// </summary>
        /// <param name="plainData">The input data to compute hash for.</param>
        /// <returns>The computed MD5 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static byte[] ComputeHash(byte[] plainData)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));

            using var md5 = MD5.Create();
            return md5.ComputeHash(plainData);
        }
    }
}