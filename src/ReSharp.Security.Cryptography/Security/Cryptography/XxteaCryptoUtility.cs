// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides XXTEA cryptographic service.
    /// </summary>
    public static class XxteaCryptoUtility
    {
        /// <summary>
        /// Encrypts the specified plain data using XXTEA algorithm.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="key">The optional key data. If null, a default key will be used.</param>
        /// <returns>The encrypted data, or null if encryption fails.</returns>
        public static byte[]? Encrypt(byte[] plainData, byte[]? key = null)
        {
            return Xxtea.Encrypt(plainData, key);
        }

        /// <summary>
        /// Decrypts the specified cipher data using XXTEA algorithm.
        /// </summary>
        /// <param name="cipherData">The cipher data to decrypt.</param>
        /// <param name="keyData">The optional key data. If null, a default key will be used.</param>
        /// <returns>The decrypted data, or null if decryption fails.</returns>
        public static byte[]? Decrypt(byte[] cipherData, byte[]? keyData = null)
        {
            return Xxtea.Decrypt(cipherData, keyData);
        }
    }
}