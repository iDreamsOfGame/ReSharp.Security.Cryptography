// Copyright (c) Jerry Lee. All rights reserved. Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;

// ReSharper disable AssignNullToNotNullAttribute
// ReSharper disable ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
// ReSharper disable CanSimplifyDictionaryTryGetValueWithGetValueOrDefault

namespace ReSharp.Security.Cryptography
{
    /// <summary>
    /// Provides RSA cryptographic service.
    /// </summary>
    public static class RsaCryptoUtility
    {
        private static readonly Dictionary<RSAEncryptionPadding, int> RsaEncryptionPaddingOverheads = new Dictionary<RSAEncryptionPadding, int>
        {
            { RSAEncryptionPadding.Pkcs1, 11 },
            { RSAEncryptionPadding.OaepSHA1, 42 },
            { RSAEncryptionPadding.OaepSHA256, 66 },
            { RSAEncryptionPadding.OaepSHA384, 98 },
            { RSAEncryptionPadding.OaepSHA512, 130 }
        };

        /// <summary>
        /// Encrypts a string and returns the result as a hexadecimal string.
        /// </summary>
        /// <param name="plainText">The plain text string to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <param name="toUppercase">Specifies whether to convert the hex string to uppercase. Defaults to true.</param>
        /// <param name="padding">The RSA encryption padding mode. Defaults to PKCS1 if not specified.</param>
        /// <returns>The encrypted data as a hexadecimal string.</returns>
        public static string EncrpytToHexString(string plainText,
            string publicKey,
            Encoding? encoding = null,
            bool toUppercase = true,
            RSAEncryptionPadding? padding = null)
        {
            return HexConverter.ToHexString(Encrypt(plainText, publicKey, encoding, padding), toUppercase);
        }

        /// <summary>
        /// Encrypts byte data and returns the result as a hexadecimal string.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="toUppercase">Specifies whether to convert the hex string to uppercase. Defaults to true.</param>
        /// <param name="padding">The RSA encryption padding mode. Defaults to PKCS1 if not specified.</param>
        /// <returns>The encrypted data as a hexadecimal string.</returns>
        public static string EncrpytToHexString(byte[] plainData,
            string publicKey,
            bool toUppercase = true,
            RSAEncryptionPadding? padding = null)
        {
            return HexConverter.ToHexString(Encrypt(plainData, publicKey, padding), toUppercase);
        }

        /// <summary>
        /// Encrypts a string and returns the result as a Base64 string.
        /// </summary>
        /// <param name="plainText">The plain text string to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <param name="padding">The RSA encryption padding mode. Defaults to PKCS1 if not specified.</param>
        /// <returns>The encrypted data as a Base64 string.</returns>
        public static string EncrpytToBase64String(string plainText,
            string publicKey,
            Encoding? encoding = null,
            RSAEncryptionPadding? padding = null)
        {
            return Convert.ToBase64String(Encrypt(plainText, publicKey, encoding, padding));
        }

        /// <summary>
        /// Encrypts byte data and returns the result as a Base64 string.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="padding">The RSA encryption padding mode. Defaults to PKCS1 if not specified.</param>
        /// <returns>The encrypted data as a Base64 string.</returns>
        public static string EncrpytToBase64String(byte[] plainData, string publicKey, RSAEncryptionPadding? padding = null)
        {
            return Convert.ToBase64String(Encrypt(plainData, publicKey, padding));
        }

        /// <summary>
        /// Encrypts a string using RSA algorithm with the specified public key.
        /// </summary>
        /// <param name="plainText">The plain text string to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8 if not specified.</param>
        /// <param name="padding">The RSA encryption padding mode. Defaults to PKCS1 if not specified.</param>
        /// <returns>The encrypted data as a byte array, or null if the input text is null or empty.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the plain text is null or empty.</exception>
        public static byte[]? Encrypt(string plainText,
            string publicKey,
            Encoding? encoding = null,
            RSAEncryptionPadding? padding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            
            encoding ??= Encoding.UTF8;
            return Encrypt(encoding.GetBytes(plainText), publicKey, padding);
        }
        
        /// <summary>
        /// Encrypts data using RSA algorithm with the specified public key.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="padding">The RSA encryption padding mode. Defaults to PKCS1 if not specified.</param>
        /// <returns>The encrypted cipher data as a byte array, or null if the input data is null or empty.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the public key is null or empty.</exception>
        /// <remarks>
        /// This method supports chunked encryption for large data inputs. 
        /// The buffer size is calculated based on the RSA key size minus the padding overhead (11 bytes for PKCS1).
        /// </remarks>
        public static byte[]? Encrypt(byte[] plainData, string publicKey, RSAEncryptionPadding? padding = null)
        {
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentNullException(nameof(publicKey));

            if (plainData == null || plainData.Length == 0)
                return plainData;

            padding ??= RSAEncryptionPadding.Pkcs1;
            return padding == RSAEncryptionPadding.Pkcs1 || padding == RSAEncryptionPadding.OaepSHA1 
                ? InternalEncryptWithDotNet(plainData, publicKey, padding)
                : InternalEncryptWithBouncyCastle(plainData, publicKey, padding);
        }

        /// <summary>
        /// Decrypts data using RSA algorithm with the specified private key.
        /// </summary>
        /// <param name="cipherData">The cipher data to decrypt.</param>
        /// <param name="privateKey">The PEM-formatted private key string.</param>
        /// <param name="padding">The RSA encryption padding mode. Defaults to PKCS1 if not specified.</param>
        /// <returns>The decrypted plain data as a byte array, or null if the input data is null or empty.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the private key is null or empty.</exception>
        /// <remarks>
        /// This method supports chunked decryption for large data inputs.
        /// The buffer size is calculated based on the RSA key size.
        /// </remarks>
        public static byte[]? Decrypt(byte[] cipherData, string privateKey, RSAEncryptionPadding? padding = null)
        {
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentNullException(nameof(privateKey));

            if (cipherData == null || cipherData.Length == 0)
                return cipherData;

            padding ??= RSAEncryptionPadding.Pkcs1;

            return padding == RSAEncryptionPadding.Pkcs1 || padding == RSAEncryptionPadding.OaepSHA1 
                ? InternalDecryptWithDotNet(cipherData, privateKey, padding)
                : InternalDecryptWithBouncyCastle(cipherData, privateKey, padding);
        }

        /// <summary>
        /// Encrypts data using .NET's built-in RSA implementation.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="padding">The RSA encryption padding mode.</param>
        /// <returns>The encrypted cipher data as a byte array.</returns>
        /// <remarks>
        /// This method supports chunked encryption for large data inputs.
        /// The buffer size is calculated based on the RSA key size minus the padding overhead.
        /// </remarks>
        internal static byte[] InternalEncryptWithDotNet(byte[] plainData, string publicKey, RSAEncryptionPadding padding)
        {
            if (!RsaEncryptionPaddingOverheads.TryGetValue(padding, out var overhead))
                overhead = 1;

            using var rsa = RSA.Create();
            rsa.ImportParameters(FromPemPublicKey(publicKey));
            var bufferSize = rsa.KeySize / 8 - overhead;
            var buffer = new byte[bufferSize];
            using MemoryStream inputStream = new MemoryStream(plainData), outputStream = new MemoryStream();
            while (true)
            {
                var readSize = inputStream.Read(buffer, 0, bufferSize);
                if (readSize <= 0)
                    break;

                var temp = new byte[readSize];
                Array.Copy(buffer, 0, temp, 0, readSize);
                var encryptedBytes = rsa.Encrypt(temp, padding);
                outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
            }

            return outputStream.ToArray();
        }

        /// <summary>
        /// Encrypts data using BouncyCastle's RSA implementation.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <param name="padding">The RSA encryption padding mode.</param>
        /// <returns>The encrypted cipher data as a byte array.</returns>
        /// <exception cref="FormatException">Thrown when the public key format is invalid.</exception>
        /// <remarks>
        /// This method supports chunked encryption for large data inputs.
        /// Uses OAEP encoding with the specified hash algorithm.
        /// </remarks>
        internal static byte[] InternalEncryptWithBouncyCastle(byte[] plainData, string publicKey, RSAEncryptionPadding padding)
        {
            var rsaKeyParameters = CreateRsaKeyParameters(publicKey);
            if (rsaKeyParameters == null)
                throw new FormatException(nameof(publicKey));
            
            var rsaEngine = new RsaEngine();
            var hash = GetDigest(padding);
            var mgf1Hash = GetDigest(padding);
            var oaepEncoding = new OaepEncoding(rsaEngine, hash, mgf1Hash, null);
            oaepEncoding.Init(true, rsaKeyParameters);
            
            var keySize = rsaKeyParameters.Modulus.BitLength / 8;
            if (!RsaEncryptionPaddingOverheads.TryGetValue(padding, out var overhead))
                overhead = 1;
            
            var maxBlockSize = keySize - overhead;
            
            using var inputStream = new MemoryStream(plainData);
            using var outputStream = new MemoryStream();
            var buffer = new byte[maxBlockSize];
            
            while (true)
            {
                var readSize = inputStream.Read(buffer, 0, maxBlockSize);
                if (readSize <= 0)
                    break;
                
                var temp = new byte[readSize];
                Array.Copy(buffer, 0, temp, 0, readSize);
                var encryptedBytes = oaepEncoding.ProcessBlock(temp, 0, temp.Length);
                outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
            }
            
            return outputStream.ToArray();
        }
        
        /// <summary>
        /// Decrypts data using .NET's built-in RSA implementation.
        /// </summary>
        /// <param name="cipherData">The cipher data to decrypt.</param>
        /// <param name="privateKey">The PEM-formatted private key string.</param>
        /// <param name="padding">The RSA encryption padding mode.</param>
        /// <returns>The decrypted plain data as a byte array.</returns>
        /// <remarks>
        /// This method supports chunked decryption for large data inputs.
        /// The buffer size is calculated based on the RSA key size.
        /// </remarks>
        internal static byte[] InternalDecryptWithDotNet(byte[] cipherData, string privateKey, RSAEncryptionPadding padding)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(FromPemPrivateKey(privateKey));
            var bufferSize = rsa.KeySize / 8;
            var buffer = new byte[bufferSize];
            using MemoryStream inputStream = new MemoryStream(cipherData), outputStream = new MemoryStream();
            while (true)
            {
                var readSize = inputStream.Read(buffer, 0, bufferSize);
                if (readSize <= 0)
                    break;

                var temp = new byte[readSize];
                Array.Copy(buffer, 0, temp, 0, readSize);
                var rawBytes = rsa.Decrypt(temp, padding);
                outputStream.Write(rawBytes, 0, rawBytes.Length);
            }

            return outputStream.ToArray();
        }
        
        /// <summary>
        /// Decrypts data using BouncyCastle's RSA implementation.
        /// </summary>
        /// <param name="cipherData">The cipher data to decrypt.</param>
        /// <param name="privateKeyPem">The PEM-formatted private key string.</param>
        /// <param name="padding">The RSA encryption padding mode.</param>
        /// <returns>The decrypted plain data as a byte array.</returns>
        /// <exception cref="FormatException">Thrown when the private key format is invalid.</exception>
        /// <remarks>
        /// This method supports chunked decryption for large data inputs.
        /// Uses OAEP encoding with the specified hash algorithm.
        /// </remarks>
        internal static byte[] InternalDecryptWithBouncyCastle(byte[] cipherData, string privateKeyPem, RSAEncryptionPadding padding)
        {
            var privateKeyParameters = CreateRsaPrivateCrtKeyParameters(privateKeyPem);
            if (privateKeyParameters == null)
                throw new FormatException(nameof(privateKeyPem));
                
            var rsaEngine = new RsaEngine();
            var hash = GetDigest(padding);
            var mgf1Hash = GetDigest(padding);
            var oaepEncoding = new OaepEncoding(rsaEngine, hash, mgf1Hash, null);
            oaepEncoding.Init(false, privateKeyParameters);
            
            var keySize = privateKeyParameters.Modulus.BitLength / 8;

            using var inputStream = new MemoryStream(cipherData);
            using var outputStream = new MemoryStream();
            var buffer = new byte[keySize];
            
            while (true)
            {
                var readSize = inputStream.Read(buffer, 0, keySize);
                if (readSize <= 0)
                    break;
                
                var temp = new byte[readSize];
                Array.Copy(buffer, 0, temp, 0, readSize);
                var decryptedBytes = oaepEncoding.ProcessBlock(temp, 0, temp.Length);
                outputStream.Write(decryptedBytes, 0, decryptedBytes.Length);
            }
            
            return outputStream.ToArray();
        }
        
        /// <summary>
        /// Converts a PEM-formatted public key string to an RSAParameters structure.
        /// </summary>
        /// <param name="publicKey">The PEM-formatted public key string.</param>
        /// <returns>An RSAParameters structure containing the public key components.</returns>
        /// <exception cref="FormatException">Thrown when the public key format is invalid.</exception>
        internal static RSAParameters FromPemPublicKey(string publicKey)
        {
            var rsaKeyParameters = CreateRsaKeyParameters(publicKey);
            if (rsaKeyParameters == null)
                throw new FormatException(nameof(publicKey));
            
            return new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
        }

        /// <summary>
        /// Converts an RSAParameters structure to a PEM-formatted public key string.
        /// </summary>
        /// <param name="rsaParameters">The RSAParameters structure containing the public key components.</param>
        /// <returns>A PEM-formatted public key string.</returns>
        internal static string ToPemPublicKey(RSAParameters rsaParameters)
        {
            var rsaKeyParameters = new RsaKeyParameters(false,
                new BigInteger(1, rsaParameters.Modulus),
                new BigInteger(1, rsaParameters.Exponent));
            using var memoryStream = new MemoryStream();
            using var streamWriter = new StreamWriter(memoryStream);
            var pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(rsaKeyParameters);
            streamWriter.Flush();

            var buffer = new byte[memoryStream.Length];
            memoryStream.Position = 0;
            _ = memoryStream.Read(buffer, 0, (int)memoryStream.Length);
            return Encoding.UTF8.GetString(buffer);
        }

        /// <summary>
        /// Converts a PEM-formatted private key string to an RSAParameters structure.
        /// </summary>
        /// <param name="privateKey">The PEM-formatted private key string.</param>
        /// <returns>An RSAParameters structure containing the private key components.</returns>
        /// <exception cref="FormatException">Thrown when the private key format is invalid.</exception>
        internal static RSAParameters FromPemPrivateKey(string privateKey)
        {
            var privateKeyParameters = CreateRsaPrivateCrtKeyParameters(privateKey);
            if (privateKeyParameters == null)
                throw new FormatException(nameof(privateKey));
                
            return new RSAParameters
            {
                Modulus = privateKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = privateKeyParameters.PublicExponent.ToByteArrayUnsigned(),
                D = privateKeyParameters.Exponent.ToByteArrayUnsigned(),
                P = privateKeyParameters.P.ToByteArrayUnsigned(),
                Q = privateKeyParameters.Q.ToByteArrayUnsigned(),
                DP = privateKeyParameters.DP.ToByteArrayUnsigned(),
                DQ = privateKeyParameters.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKeyParameters.QInv.ToByteArrayUnsigned(),
            };
        }

        /// <summary>
        /// Converts an RSAParameters structure to a PEM-formatted private key string.
        /// </summary>
        /// <param name="rsaParameters">The RSAParameters structure containing the private key components.</param>
        /// <returns>A PEM-formatted private key string.</returns>
        internal static string ToPemPrivateKey(RSAParameters rsaParameters)
        {
            var rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, rsaParameters.Modulus),
                new BigInteger(1, rsaParameters.Exponent),
                new BigInteger(1, rsaParameters.D),
                new BigInteger(1, rsaParameters.P),
                new BigInteger(1, rsaParameters.Q),
                new BigInteger(1, rsaParameters.DP),
                new BigInteger(1, rsaParameters.DQ),
                new BigInteger(1, rsaParameters.InverseQ));

            using var memoryStream = new MemoryStream();
            using var streamWriter = new StreamWriter(memoryStream);
            var pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(rsaPrivateCrtKeyParameters);
            streamWriter.Flush();

            var buffer = new byte[memoryStream.Length];
            memoryStream.Position = 0;
            _ = memoryStream.Read(buffer, 0, (int)memoryStream.Length);
            return Encoding.UTF8.GetString(buffer);
        }

        /// <summary>
        /// Creates an RsaKeyParameters object from a PEM-formatted public key string.
        /// </summary>
        /// <param name="publicKeyPem">The PEM-formatted public key string.</param>
        /// <returns>An RsaKeyParameters object, or null if the key format is invalid.</returns>
        private static RsaKeyParameters? CreateRsaKeyParameters(string publicKeyPem)
        {
            using var reader = new StringReader(publicKeyPem);
            var pemReader = new PemReader(reader);
            return pemReader.ReadObject() as RsaKeyParameters;
        }
        
        /// <summary>
        /// Creates an RsaPrivateCrtKeyParameters object from a PEM-formatted private key string.
        /// </summary>
        /// <param name="privateKeyPem">The PEM-formatted private key string.</param>
        /// <returns>An RsaPrivateCrtKeyParameters object, or null if the key format is invalid.</returns>
        /// <remarks>
        /// Handles both AsymmetricCipherKeyPair and direct RsaPrivateCrtKeyParameters formats.
        /// </remarks>
        private static RsaPrivateCrtKeyParameters? CreateRsaPrivateCrtKeyParameters(string privateKeyPem)
        {
            using var reader = new StringReader(privateKeyPem);
            var pemReader = new PemReader(reader);
            var pemObject = pemReader.ReadObject();
        
            RsaPrivateCrtKeyParameters? privateKeyParams;
            if (pemObject is AsymmetricCipherKeyPair asymmetricCipherKeyPair)
            {
                privateKeyParams = asymmetricCipherKeyPair.Private as RsaPrivateCrtKeyParameters;
            }
            else
            {
                privateKeyParams = pemObject as RsaPrivateCrtKeyParameters;
            }

            return privateKeyParams;
        }

        /// <summary>
        /// Gets the appropriate digest algorithm for the specified RSA encryption padding.
        /// </summary>
        /// <param name="padding">The RSA encryption padding mode.</param>
        /// <returns>An IDigest instance corresponding to the padding mode.</returns>
        private static IDigest GetDigest(RSAEncryptionPadding padding)
        {
            if (padding == RSAEncryptionPadding.OaepSHA256)
                return new Sha256Digest();
            
            if (padding == RSAEncryptionPadding.OaepSHA384)
                return new Sha384Digest();
            
            if (padding == RSAEncryptionPadding.OaepSHA512)
                return new Sha512Digest();
            
            return new Sha1Digest();
        }
    }
}