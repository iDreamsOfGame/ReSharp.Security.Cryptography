// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides SHA hash cryptographic service.
    /// </summary>
    public static class ShaCryptoUtility
    {
        #region SHA1
        
        /// <summary>
        /// Computes the SHA1 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA1 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha1HashToHexString(byte[] rawData, bool toUppercase = true)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha1Hash(rawData);
            var hexString = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            return toUppercase ? hexString : hexString.ToLower();
        }
        
        /// <summary>
        /// Computes the SHA1 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA1 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha1HashToBase64String(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha1Hash(rawData);
            return Convert.ToBase64String(hashBytes);
        }
        
        /// <summary>
        /// Computes the SHA1 hash of the input data.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA1 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static byte[] ComputeSha1Hash(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(rawData);
        }

        #endregion

        #region SHA256
        
        /// <summary>
        /// Computes the SHA256 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA256 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha256HashToHexString(byte[] rawData, bool toUppercase = true)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha256Hash(rawData);
            var hexString = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            return toUppercase ? hexString : hexString.ToLower();
        }
        
        /// <summary>
        /// Computes the SHA256 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA256 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha256HashToBase64String(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha256Hash(rawData);
            return Convert.ToBase64String(hashBytes);
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
        /// Computes the SHA384 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA384 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha384HashToHexString(byte[] rawData, bool toUppercase = true)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha384Hash(rawData);
            var hexString = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            return toUppercase ? hexString : hexString.ToLower();
        }
        
        /// <summary>
        /// Computes the SHA384 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA384 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha384HashToBase64String(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha384Hash(rawData);
            return Convert.ToBase64String(hashBytes);
        }
        
        /// <summary>
        /// Computes the SHA384 hash of the input data.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA384 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static byte[] ComputeSha384Hash(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            using var sha384 = SHA384.Create();
            return sha384.ComputeHash(rawData);
        }
        
        #endregion
        
        #region SHA512
        
        /// <summary>
        /// Computes the SHA512 hash of the input data and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <param name="toUppercase">If true, returns uppercase hex string; otherwise lowercase. Default is true.</param>
        /// <returns>SHA512 hash as a hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha512HashToHexString(byte[] rawData, bool toUppercase = true)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha512Hash(rawData);
            var hexString = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            return toUppercase ? hexString : hexString.ToLower();
        }
        
        /// <summary>
        /// Computes the SHA512 hash of the input data and returns it as a Base64 string.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA512 hash as a Base64 string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static string ComputeSha512HashToBase64String(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            var hashBytes = ComputeSha512Hash(rawData);
            return Convert.ToBase64String(hashBytes);
        }
        
        /// <summary>
        /// Computes the SHA512 hash of the input data.
        /// </summary>
        /// <param name="rawData">The input data to hash.</param>
        /// <returns>SHA512 hash as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rawData is null or empty.</exception>
        public static byte[] ComputeSha512Hash(byte[] rawData)
        {
            if (rawData == null || rawData.Length == 0)
                throw new ArgumentNullException(nameof(rawData));

            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(rawData);
        }
        
        #endregion
    }
}