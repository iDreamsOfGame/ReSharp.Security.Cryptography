// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides AES cryptographic service.
    /// </summary>
    public static class AesCryptoUtility
    {
        /// <summary>
        /// Encrypts a byte array with AES algorithm.
        /// </summary>
        /// <param name="plainData">The plain byte array data to encrypt.</param>
        /// <param name="key">The key byte array for encryption.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes.</param>
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
        /// <param name="key">The key byte array for decryption.</param>
        /// <param name="iv">The initialization vector byte array. Optional for ECB mode, required for other modes.</param>
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