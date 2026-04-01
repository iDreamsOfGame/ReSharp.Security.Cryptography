// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides AES (Advanced Encryption Standard) cryptographic operations for encrypting and decrypting data.
    /// Supports multiple cipher modes (CBC, ECB, etc.) and padding modes with various output formats (Hex, Base64).
    /// </summary>
    public static class AesCryptoUtility
    {
        /// <summary>
        /// Encrypts a string using AES algorithm and returns the result as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The plain text string to encrypt.</param>
        /// <param name="key">The key byte array for encryption. Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes like CBC.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise returns lowercase. Default is true.</param>
        /// <param name="cipherMode">The cipher mode to use. Default is CBC (Cipher Block Chaining).</param>
        /// <param name="paddingMode">The padding mode to use. Default is PKCS7.</param>
        /// <returns>The encrypted data as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <c>plainText</c> is null or empty, or when <c>key</c> is null or empty.</exception>
        public static string EncryptToHexString(string plainText,
            byte[] key,
            byte[]? iv = null,
            Encoding? encoding = null,
            bool toUppercase = true,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            var cipherData = Encrypt(plainText, key, iv, encoding, cipherMode, paddingMode);
            return HexConverter.ToHexString(cipherData, toUppercase);
        }

        /// <summary>
        /// Encrypts a byte array using AES algorithm and returns the result as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The plain byte array data to encrypt.</param>
        /// <param name="key">The key byte array for encryption. Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes like CBC.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <param name="cipherMode">The cipher mode. Default is CBC.</param>
        /// <param name="paddingMode">The padding mode. Default is PKCS7.</param>
        /// <returns>The encrypted data as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <c>plainData</c> or <c>key</c> is null or empty.</exception>
        public static string EncryptToHexString(byte[] plainData,
            byte[] key,
            byte[]? iv = null,
            bool toUppercase = true,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            var cipherData = Encrypt(plainData, key, iv, cipherMode, paddingMode);
            return HexConverter.ToHexString(cipherData, toUppercase);
        }
        
        /// <summary>
        /// Encrypts a string using AES algorithm and returns the result as a Base64 string.
        /// </summary>
        /// <param name="plainText">The plain text string to encrypt.</param>
        /// <param name="key">The key byte array for encryption. Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes like CBC.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <param name="cipherMode">The cipher mode. Default is CBC.</param>
        /// <param name="paddingMode">The padding mode. Default is PKCS7.</param>
        /// <returns>The encrypted data as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <c>plainText</c> is null or empty, or when <c>key</c> is null or empty.</exception>
        public static string EncryptToBase64String(string plainText,
            byte[] key,
            byte[]? iv = null,
            Encoding? encoding = null,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Convert.ToBase64String(Encrypt(plainText, key, iv, encoding, cipherMode, paddingMode));
        }

        /// <summary>
        /// Encrypts a byte array using AES algorithm and returns the result as a Base64 string.
        /// </summary>
        /// <param name="plainData">The plain byte array data to encrypt.</param>
        /// <param name="key">The key byte array for encryption. Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes like CBC.</param>
        /// <param name="cipherMode">The cipher mode. Default is CBC.</param>
        /// <param name="paddingMode">The padding mode. Default is PKCS7.</param>
        /// <returns>The encrypted data as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <c>plainData</c> or <c>key</c> is null or empty.</exception>
        public static string EncryptToBase64String(byte[] plainData,
            byte[] key,
            byte[]? iv = null,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return Convert.ToBase64String(Encrypt(plainData, key, iv, cipherMode, paddingMode));
        }
        
        /// <summary>
        /// Encrypts a string using AES algorithm and returns the encrypted byte array.
        /// </summary>
        /// <param name="plainText">The plain text string to encrypt.</param>
        /// <param name="key">The key byte array for encryption. Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes like CBC.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <param name="cipherMode">The cipher mode. Default is CBC.</param>
        /// <param name="paddingMode">The padding mode. Default is PKCS7.</param>
        /// <returns>The encrypted byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <c>plainText</c> is null or empty, or when <c>key</c> is null or empty.</exception>
        public static byte[] Encrypt(string plainText,
            byte[] key,
            byte[]? iv = null,
            Encoding? encoding = null,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));

            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            encoding ??= Encoding.UTF8;
            return Encrypt(encoding.GetBytes(plainText), key, iv, cipherMode, paddingMode);
        }

        /// <summary>
        /// Encrypts a byte array with AES algorithm.
        /// </summary>
        /// <param name="plainData">The plain byte array data to encrypt.</param>
        /// <param name="key">The key byte array for encryption. Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes like CBC.</param>
        /// <param name="cipherMode">The cipher mode. Default is CBC.</param>
        /// <param name="paddingMode">The padding mode. Default is PKCS7.</param>
        /// <returns>The encrypted byte array.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <c>plainData</c> or <c>key</c> is null or empty, or when <c>iv</c> is required but not provided.
        /// </exception>
        public static byte[] Encrypt(byte[] plainData,
            byte[] key,
            byte[]? iv = null,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));

            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            if (cipherMode != CipherMode.ECB && (iv == null || iv.Length == 0))
                throw new ArgumentNullException(nameof(iv));

            using var aes = Aes.Create();
            aes.Key = key;

            if (iv != null && iv.Length > 0)
                aes.IV = iv;

            aes.Mode = cipherMode;
            aes.Padding = paddingMode;
            return aes.CreateEncryptor().TransformFinalBlock(plainData, 0, plainData.Length);
        }

        /// <summary>
        /// Decrypts a byte array with AES algorithm.
        /// </summary>
        /// <param name="cipherData">The cipher byte array data to decrypt.</param>
        /// <param name="key">The key byte array for decryption. Must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes like CBC.</param>
        /// <param name="cipherMode">The cipher mode. Default is CBC.</param>
        /// <param name="paddingMode">The padding mode. Default is PKCS7.</param>
        /// <returns>The decrypted byte array.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <c>cipherData</c> or <c>key</c> is null or empty, or when <c>iv</c> is required but not provided.
        /// </exception>
        public static byte[] Decrypt(byte[] cipherData,
            byte[] key,
            byte[]? iv = null,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (cipherData == null || cipherData.Length == 0)
                throw new ArgumentNullException(nameof(cipherData));

            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            if (cipherMode != CipherMode.ECB && (iv == null || iv.Length == 0))
                throw new ArgumentNullException(nameof(iv));

            using var aes = Aes.Create();
            aes.Key = key;

            if (iv != null && iv.Length > 0)
                aes.IV = iv;

            aes.Mode = cipherMode;
            aes.Padding = paddingMode;
            return aes.CreateDecryptor().TransformFinalBlock(cipherData, 0, cipherData.Length);
        }
    }
}