// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides SHA hash cryptographic service.
    /// </summary>
    public static class ShaCryptoUtility
    {
        #region SHA1
        
        /// <summary>
        /// Computes the SHA1 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA1 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha1HashToHexString(string plainText, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeSha1Hash(plainText, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the SHA1 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA1 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha1HashToHexString(byte[] plainData, bool toUppercase = true)
        {
            var hashCode = ComputeSha1Hash(plainData);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the SHA1 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA1 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha1HashToBase64String(string plainText, Encoding? encoding = null)
        {
            var hashCode = ComputeSha1Hash(plainText, encoding);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the SHA1 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <returns>SHA1 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha1HashToBase64String(byte[] plainData)
        {
            var hashCode = ComputeSha1Hash(plainData);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the SHA1 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA1 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static byte[] ComputeSha1Hash(string plainText, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            
            encoding ??= Encoding.UTF8;
            return ComputeSha1Hash(encoding.GetBytes(plainText));
        }
        
        /// <summary>
        /// Computes the SHA1 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <returns>SHA1 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static byte[] ComputeSha1Hash(byte[] plainData)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));

            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(plainData);
        }

        #endregion

        #region SHA256
        
        /// <summary>
        /// Computes the SHA256 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA256 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha256HashToHexString(string plainText, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeSha256Hash(plainText, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the SHA256 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA256 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha256HashToHexString(byte[] plainData, bool toUppercase = true)
        {
            var hashCode = ComputeSha256Hash(plainData);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the SHA256 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA256 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha256HashToBase64String(string plainText, Encoding? encoding = null)
        {
            var hashCode = ComputeSha256Hash(plainText, encoding);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the SHA256 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <returns>SHA256 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha256HashToBase64String(byte[] plainData)
        {
            var hashCode = ComputeSha256Hash(plainData);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the SHA256 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA256 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static byte[] ComputeSha256Hash(string plainText, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
        
            encoding ??= Encoding.UTF8;
            return ComputeSha256Hash(encoding.GetBytes(plainText));
        }

        /// <summary>
        /// Computes the SHA256 hash of the input data.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA256 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static byte[] ComputeSha256Hash(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(rawData);
        }

        #endregion
        
        #region SHA384
        
        /// <summary>
        /// Computes the SHA384 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA384 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha384HashToHexString(string plainText, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeSha384Hash(plainText, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the SHA384 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA384 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha384HashToHexString(byte[] plainData, bool toUppercase = true)
        {
            var hashCode = ComputeSha384Hash(plainData);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the SHA384 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA384 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha384HashToBase64String(string plainText, Encoding? encoding = null)
        {
            var hashCode = ComputeSha384Hash(plainText, encoding);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the SHA384 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <returns>SHA384 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha384HashToBase64String(byte[] plainData)
        {
            var hashCode = ComputeSha384Hash(plainData);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the SHA384 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA384 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static byte[] ComputeSha384Hash(string plainText, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
        
            encoding ??= Encoding.UTF8;
            return ComputeSha384Hash(encoding.GetBytes(plainText));
        }
        
        /// <summary>
        /// Computes the SHA384 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <returns>SHA384 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static byte[] ComputeSha384Hash(byte[] plainData)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));

            using var sha384 = SHA384.Create();
            return sha384.ComputeHash(plainData);
        }
        
        #endregion
        
        #region SHA512
        
        /// <summary>
        /// Computes the SHA512 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA512 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha512HashToHexString(string plainText, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeSha512Hash(plainText, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the SHA512 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA512 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha512HashToHexString(byte[] plainData, bool toUppercase = true)
        {
            var hashCode = ComputeSha512Hash(plainData);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the SHA512 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA512 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static string ComputeSha512HashToBase64String(string plainText, Encoding? encoding = null)
        {
            var hashCode = ComputeSha512Hash(plainText, encoding);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the SHA512 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <returns>SHA512 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static string ComputeSha512HashToBase64String(byte[] plainData)
        {
            var hashCode = ComputeSha512Hash(plainData);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the SHA512 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>SHA512 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText is null or empty.</exception>
        public static byte[] ComputeSha512Hash(string plainText, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
        
            encoding ??= Encoding.UTF8;
            return ComputeSha512Hash(encoding.GetBytes(plainText));
        }
        
        /// <summary>
        /// Computes the SHA512 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <returns>SHA512 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData is null or empty.</exception>
        public static byte[] ComputeSha512Hash(byte[] plainData)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));

            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(plainData);
        }
        
        #endregion
    }
}