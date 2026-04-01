// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable ReturnTypeCanBeEnumerable.Global
// ReSharper disable ConvertToUsingDeclaration

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides common cryptographic service.
    /// </summary>
    public static class CryptoUtility
    {
        internal const string LowercaseCharacters = "abcdefghijklmnopqrstuvwxyz";
        
        internal const string UppercaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        
        internal const string Numbers = "0123456789";

        internal const string SpecialCharacters = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        /// <summary>
        /// Generates the random key byte array for encryption. 
        /// </summary>
        /// <param name="length">The length of key byte array. </param>
        /// <returns>The key byte array for encryption. </returns>
        /// <exception cref="ArgumentOutOfRangeException">Length must be greater than 0.</exception>
        public static byte[] GenerateRandomKey(int length = 16)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be greater than 0.");
            
            var key = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            return key;
        }

        /// <summary>
        /// Generates the random key string for encryption, which is original plain text that encoding by UTF-8. 
        /// </summary>
        /// <param name="length">The length of key string. </param>
        /// <param name="includeLowercaseCharacters">if set to <c>true</c> [include lowercase characters]. </param>
        /// <param name="includeUppercaseCharacters">if set to <c>true</c> [include uppercase characters]. </param>
        /// <param name="includeNumbers">if set to <c>true</c> [include numbers]. </param>
        /// <param name="includeSpecialCharacters">if set to <c>true</c> [include special characters]. </param>
        /// <returns>The key string for encryption, which is original plain text that encoding by UTF-8. </returns>
        public static string GenerateRandomKeyString(int length = 16,
            bool includeLowercaseCharacters = true,
            bool includeUppercaseCharacters = true,
            bool includeNumbers = true,
            bool includeSpecialCharacters = true)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be greater than 0.");

            var group = new StringBuilder();

            if (includeLowercaseCharacters)
                group.Append(LowercaseCharacters);

            if (includeUppercaseCharacters)
                group.Append(UppercaseCharacters);
            
            if (includeNumbers)
                group.Append(Numbers);

            if (includeSpecialCharacters)
                group.Append(SpecialCharacters);

            var groupString = group.ToString();

            if (groupString.Length == 0)
                throw new ArgumentException("At least one character type must be included.", nameof(includeNumbers));

            var result = new StringBuilder();
            var buffer = new byte[4];

            using var rng = RandomNumberGenerator.Create();
            for (var i = 0; i < length; i++)
            {
                rng.GetBytes(buffer);
                var index = BitConverter.ToInt32(buffer, 0) % groupString.Length;
                if (index < 0)
                    index = ~index;
                result.Append(groupString[index]);
            }

            return result.ToString();
        }
    }
}