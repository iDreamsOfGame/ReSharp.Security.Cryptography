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
        public static byte[]? Encrypt(byte[]? plainData, string publicKey, RSAEncryptionPadding? padding = null)
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
        public static byte[]? Decrypt(byte[]? cipherData, string privateKey, RSAEncryptionPadding? padding = null)
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

        private static RsaKeyParameters? CreateRsaKeyParameters(string publicKeyPem)
        {
            using var reader = new StringReader(publicKeyPem);
            var pemReader = new PemReader(reader);
            return pemReader.ReadObject() as RsaKeyParameters;
        }
        
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