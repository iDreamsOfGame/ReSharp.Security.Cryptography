using System;
using System.Security.Cryptography;
using System.Text;

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides HMAC-MD5 hash cryptographic service.
    /// </summary>
    public static class HmacMd5CryptoUtility
    {
        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified string and returns a substring of the hexadecimal representation.
        /// </summary>
        public static string ComputeHashToHexSubstring(string plainText, string key, Encoding? encoding = null, bool toUppercase = true)
        { 
            var hexString = ComputeHashToHexString(plainText, key, encoding, toUppercase);
            return hexString.Substring(8, 16);
        }
        
        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified byte array and returns a substring of the hexadecimal representation.
        /// </summary>
        public static string ComputeHashToHexSubstring(byte[] plainData, byte[] key, bool toUppercase = true)
        {
            var hexString = ComputeHashToHexString(plainData, key, toUppercase);
            return hexString.Substring(8, 16);
        }

        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified string and returns the hexadecimal representation.
        /// </summary>
        public static string ComputeHashToHexString(string plainText, string key, Encoding? encoding = null, bool toUppercase = true)
        {
            var hashCode = ComputeHash(plainText, key, encoding);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }
        
        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified byte array and returns the hexadecimal representation.
        /// </summary>
        public static string ComputeHashToHexString(byte[] plainData, byte[] key, bool toUppercase = true)
        {
            var hashCode = ComputeHash(plainData, key);
            return HexConverter.ToHexString(hashCode, toUppercase);
        }

        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified string and returns a Base64-encoded substring of the hash.
        /// </summary>
        public static string ComputeHashToBase64Substring(string plainText, string key, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            var hashCode = ComputeHash(plainText, key, encoding);
            var subHashCode = new byte[hashCode.Length / 2];
            Array.Copy(hashCode, 4, subHashCode, 0, 8);
            return Convert.ToBase64String(subHashCode);
        }
        
        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified byte array and returns a Base64-encoded substring of the hash.
        /// </summary>
        public static string ComputeHashToBase64Substring(byte[] plainData, byte[] key)
        {
            var hashCode = ComputeHash(plainData, key);
            var subHashCode = new byte[hashCode.Length / 2];
            Array.Copy(hashCode, 4, subHashCode, 0, 8);
            return Convert.ToBase64String(subHashCode);
        }

        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified string and returns the Base64-encoded representation.
        /// </summary>
        public static string ComputeHashToBase64String(string plainText, string key, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            var hashCode = ComputeHash(plainText, key, encoding);
            return Convert.ToBase64String(hashCode);
        }
        
        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified byte array and returns the Base64-encoded representation.
        /// </summary>
        public static string ComputeHashToBase64String(byte[] plainData, byte[] key)
        {
            var hashCode = ComputeHash(plainData, key);
            return Convert.ToBase64String(hashCode);
        }

        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified string.
        /// </summary>
        public static byte[] ComputeHash(string plainText, string key, Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));
            
            encoding ??= Encoding.UTF8;
            return ComputeHash(encoding.GetBytes(plainText), encoding.GetBytes(key));
        }
        
        /// <summary>
        /// Computes the HMAC-MD5 hash of the specified byte array.
        /// </summary>
        public static byte[] ComputeHash(byte[] plainData, byte[] key)
        {
            if (plainData == null || plainData.Length == 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            using var hmac = new HMACMD5(key);
            return hmac.ComputeHash(plainData);
        }
    }
}