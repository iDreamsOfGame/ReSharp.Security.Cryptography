// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides HMAC cryptographic service.
    /// </summary>
    public static class HmacShaCryptoUtility
    {
        #region HMAC-SHA1

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA1 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToHexString(string plainText, byte[] key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha1Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA1 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToHexString(byte[] plainData, byte[] key, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha1Hash(plainData, key);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA1 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToBase64String(string plainText, byte[] key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha1Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA1 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToBase64String(byte[] plainData, byte[] key)
        {
            var hashCode = ComputeHmacSha1Hash(plainData, key);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA1 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha1Hash(string plainText, byte[] key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha1Hash(encoding.GetBytes(plainText), key);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA1 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha1Hash(byte[] plainData, byte[] key)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            using var hmacSha1 = new HMACSHA1(key);
            return hmacSha1.ComputeHash(plainData);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA1 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToHexString(string plainText, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha1Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA1 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToHexString(byte[] plainData, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha1Hash(plainData, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA1 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToBase64String(string plainText, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha1Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA1 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha1HashToBase64String(byte[] plainData, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha1Hash(plainData, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA1 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha1Hash(string plainText, string key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha1Hash(encoding.GetBytes(plainText), encoding.GetBytes(key));
        }

        /// <summary>
        /// Computes the HMAC-SHA1 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA1 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha1Hash(byte[] plainData, string key, Encoding? encoding = null)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha1Hash(plainData, encoding.GetBytes(key));
        }

        #endregion

        #region HMAC-SHA256

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA256 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToHexString(string plainText, byte[] key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha256Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA256 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToHexString(byte[] plainData, byte[] key, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha256Hash(plainData, key);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA256 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToBase64String(string plainText, byte[] key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha256Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA256 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToBase64String(byte[] plainData, byte[] key)
        {
            var hashCode = ComputeHmacSha256Hash(plainData, key);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA256 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha256Hash(string plainText, byte[] key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha256Hash(encoding.GetBytes(plainText), key);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA256 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha256Hash(byte[] plainData, byte[] key)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            using var hmacSha256 = new HMACSHA256(key);
            return hmacSha256.ComputeHash(plainData);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA256 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToHexString(string plainText, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha256Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA256 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToHexString(byte[] plainData, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha256Hash(plainData, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA256 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToBase64String(string plainText, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha256Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA256 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha256HashToBase64String(byte[] plainData, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha256Hash(plainData, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA256 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha256Hash(string plainText, string key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha256Hash(encoding.GetBytes(plainText), encoding.GetBytes(key));
        }

        /// <summary>
        /// Computes the HMAC-SHA256 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA256 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha256Hash(byte[] plainData, string key, Encoding? encoding = null)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha256Hash(plainData, encoding.GetBytes(key));
        }

        #endregion

        #region HMAC-SHA384

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA384 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToHexString(string plainText, byte[] key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha384Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA384 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToHexString(byte[] plainData, byte[] key, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha384Hash(plainData, key);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA384 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToBase64String(string plainText, byte[] key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha384Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA384 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToBase64String(byte[] plainData, byte[] key)
        {
            var hashCode = ComputeHmacSha384Hash(plainData, key);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA384 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha384Hash(string plainText, byte[] key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha384Hash(encoding.GetBytes(plainText), key);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA384 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha384Hash(byte[] plainData, byte[] key)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            using var hmacSha384 = new HMACSHA384(key);
            return hmacSha384.ComputeHash(plainData);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA384 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToHexString(string plainText, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha384Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA384 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToHexString(byte[] plainData, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha384Hash(plainData, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA384 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToBase64String(string plainText, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha384Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA384 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha384HashToBase64String(byte[] plainData, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha384Hash(plainData, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA384 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha384Hash(string plainText, string key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha384Hash(encoding.GetBytes(plainText), encoding.GetBytes(key));
        }

        /// <summary>
        /// Computes the HMAC-SHA384 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA384 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha384Hash(byte[] plainData, string key, Encoding? encoding = null)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha384Hash(plainData, encoding.GetBytes(key));
        }

        #endregion

        #region HMAC-SHA512

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA512 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToHexString(string plainText, byte[] key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha512Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA512 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToHexString(byte[] plainData, byte[] key, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha512Hash(plainData, key);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA512 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToBase64String(string plainText, byte[] key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha512Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA512 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToBase64String(byte[] plainData, byte[] key)
        {
            var hashCode = ComputeHmacSha512Hash(plainData, key);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA512 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha512Hash(string plainText, byte[] key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha512Hash(encoding.GetBytes(plainText), key);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <returns>HMAC-SHA512 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha512Hash(byte[] plainData, byte[] key)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            using var hmacSha512 = new HMACSHA512(key);
            return hmacSha512.ComputeHash(plainData);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input string and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA512 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToHexString(string plainText, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha512Hash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>HMAC-SHA512 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToHexString(byte[] plainData, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHmacSha512Hash(plainData, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input string and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA512 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToBase64String(string plainText, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha512Hash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA512 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static string ComputeHmacSha512HashToBase64String(byte[] plainData, string key, Encoding? encoding = null)
        {
            var hashCode = ComputeHmacSha512Hash(plainData, key, encoding);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input string.
        /// </summary>
        /// <param name="plainText">The input string to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for both plainText and key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA512 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null or empty.</exception>
        public static byte[] ComputeHmacSha512Hash(string plainText, string key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha512Hash(encoding.GetBytes(plainText), encoding.GetBytes(key));
        }

        /// <summary>
        /// Computes the HMAC-SHA512 hash of the input data.
        /// </summary>
        /// <param name="plainData">The input data to hash.</param>
        /// <param name="key">The key to use for the HMAC computation.</param>
        /// <param name="encoding">The encoding to use for key. If null, UTF8 encoding is used by default.</param>
        /// <returns>HMAC-SHA512 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainData or key is null or empty.</exception>
        public static byte[] ComputeHmacSha512Hash(byte[] plainData, string key, Encoding? encoding = null)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return ComputeHmacSha512Hash(plainData, encoding.GetBytes(key));
        }

        #endregion
    }
}