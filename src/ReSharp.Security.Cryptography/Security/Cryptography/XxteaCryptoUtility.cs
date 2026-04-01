// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Text;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides XXTEA cryptographic service.
    /// </summary>
    public static class XxteaCryptoUtility
    {
        /// <summary>
        /// Encrypts the specified plain text using XXTEA algorithm and returns the result as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The optional key data. If null, a default key will be used.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise returns lowercase. Default is true.</param>
        /// <returns>The encrypted data as a hexadecimal string, or null if encryption fails.</returns>
        public static string? EncryptToHexString(string plainText,
            byte[]? key = null,
            Encoding? encoding = null,
            bool toUppercase = true)
        {
            var cipherData = Encrypt(plainText, key, encoding);
            return cipherData != null ? HexConverter.ToHexString(cipherData, toUppercase) : null;
        }

        /// <summary>
        /// Encrypts the specified plain data using XXTEA algorithm and returns the result as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="key">The optional key data. If null, a default key will be used.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise returns lowercase. Default is true.</param>
        /// <returns>The encrypted data as a hexadecimal string, or null if encryption fails.</returns>
        public static string? EncryptToHexString(byte[] plainData, byte[]? key = null, bool toUppercase = true)
        {
            var cipherData = Encrypt(plainData, key);
            return cipherData != null ? HexConverter.ToHexString(cipherData, toUppercase) : null;
        }

        /// <summary>
        /// Encrypts the specified plain text using XXTEA algorithm and returns the result as a Base64 string.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The optional key data. If null, a default key will be used.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <returns>The encrypted data as a Base64 string, or null if encryption fails.</returns>
        public static string? EncryptToBase64String(string plainText, byte[]? key = null, Encoding? encoding = null)
        {
            var cipherData = Encrypt(plainText, key, encoding);
            return cipherData != null ? Convert.ToBase64String(cipherData) : null;
        }

        /// <summary>
        /// Encrypts the specified plain data using XXTEA algorithm and returns the result as a Base64 string.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="key">The optional key data. If null, a default key will be used.</param>
        /// <returns>The encrypted data as a Base64 string, or null if encryption fails.</returns>
        public static string? EncryptToBase64String(byte[] plainData, byte[]? key = null)
        {
            var cipherData = Encrypt(plainData, key);
            return cipherData != null ? Convert.ToBase64String(cipherData) : null;
        }

        /// <summary>
        /// Encrypts the specified plain text using XXTEA algorithm.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The optional key data. If null, a default key will be used.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <returns>The encrypted byte array, or null if encryption fails.</returns>
        public static byte[]? Encrypt(string plainText, byte[]? key = null, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            
            encoding ??= Encoding.UTF8;
            return Encrypt(encoding.GetBytes(plainText), key);
        }

        /// <summary>
        /// Encrypts the specified plain data using XXTEA algorithm.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="key">The optional key data. If null, a default key will be used.</param>
        /// <returns>The encrypted data, or null if encryption fails.</returns>
        public static byte[]? Encrypt(byte[] plainData, byte[]? key = null)
        {
            if (plainData == null)
                throw new ArgumentNullException(nameof(plainData));
            
            return Xxtea.Encrypt(plainData, key);
        }

        /// <summary>
        /// Decrypts the specified cipher text using XXTEA algorithm.
        /// </summary>
        /// <param name="cipherText">The cipher text to decrypt.</param>
        /// <param name="keyData">The optional key data. If null, a default key will be used.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <returns>The decrypted byte array, or null if decryption fails.</returns>
        public static byte[]? Decrypt(string cipherText, byte[]? keyData = null, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException(nameof(cipherText));

            encoding ??= Encoding.UTF8;
            return Decrypt(encoding.GetBytes(cipherText), keyData);
        }

        /// <summary>
        /// Decrypts the specified cipher data using XXTEA algorithm.
        /// </summary>
        /// <param name="cipherData">The cipher data to decrypt.</param>
        /// <param name="keyData">The optional key data. If null, a default key will be used.</param>
        /// <returns>The decrypted data, or null if decryption fails.</returns>
        public static byte[]? Decrypt(byte[] cipherData, byte[]? keyData = null)
        {
            if (cipherData == null)
                throw new ArgumentNullException(nameof(cipherData));
            
            return Xxtea.Decrypt(cipherData, keyData);
        }
    }
}