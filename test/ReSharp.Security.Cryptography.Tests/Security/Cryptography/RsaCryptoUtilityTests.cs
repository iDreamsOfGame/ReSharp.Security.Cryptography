using System;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace ReSharp.Security.Cryptography.Tests
{
    public class RsaCryptoUtilityTests
    {
        private const string TestRsaPkcs8PublicKey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtRGuNPACW0NfeGJZvMAh
NmSMzVNtIGSnQMPDV+twRJSvwm6UqaKsfK1lWDrBoHpFdwwZYRzuMOPHibis0uj7
Gp7Lw/LEGkr7cvvO8S3k4IKVmOzoJuyQsQA1BNVWHZScd4bWgOB2N3/DYpaRM1Dm
rq5lcgTOP4hb/mPnRtv0csUbNPVVG4RJGq5NdO7ziIJIjxAR7HCEEK+FOJpPlrdA
41ANkUWSrhCnLGoKf2fe1miRjOzTrXZaZEaDCKfGPuxLd5tqjgTfRq6IdTLo7NFk
c+lNw1EjbAqlFx4qWKBVIXB7UMlXnllybey3qTZvcbA02NxXJJ3Gmaca4rGV02Tb
mQIDAQAB
-----END PUBLIC KEY-----";

        private const string TestRsaPkcs8PrivateKey = @"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1Ea408AJbQ194
Ylm8wCE2ZIzNU20gZKdAw8NX63BElK/CbpSpoqx8rWVYOsGgekV3DBlhHO4w48eJ
uKzS6PsansvD8sQaSvty+87xLeTggpWY7Ogm7JCxADUE1VYdlJx3htaA4HY3f8Ni
lpEzUOaurmVyBM4/iFv+Y+dG2/RyxRs09VUbhEkark107vOIgkiPEBHscIQQr4U4
mk+Wt0DjUA2RRZKuEKcsagp/Z97WaJGM7NOtdlpkRoMIp8Y+7Et3m2qOBN9Groh1
Mujs0WRz6U3DUSNsCqUXHipYoFUhcHtQyVeeWXJt7LepNm9xsDTY3FckncaZpxri
sZXTZNuZAgMBAAECggEAALB4CtCNGb7YarNpJwxONBBO7ust460ua9My9684RrKQ
NrvIChtJ79GTLLJQkWVVxV3A7Ps4tuvvEwmmcskbR58qJG1UrMrzSR1HTOjBUc99
dU8VlSxaYqofCY0sXkF2FQho4aW5HX35hvMOy3S35Bta3IPDKz/AJehIdZ8Zv6QZ
0YA7BGH8BhgfNofFMh164GaKGIwc8YZn6nkDX3sVYytFkI8FpHxlpPEv/QYErGeo
pCH+GhQJCL6zLKv4PtpVcx8GAwRi1a7bnp1JyAMa3yDLce9PPtP4QAORxvJ1iwfH
zeEleOD3/XFzpLufNkqpWSOSyXhOQtViVIklm4RE7wKBgQDkjjmibus/V5ipV0xl
sZYSUHVA/ppkdICHYPgqeEc2DppyS+D8HZizig6KntTNk+WCiSpc8InExfB5W8iB
OIZ8YjIOb//yHsOxgamY7nzf11Kxkpu9ABycrgIeX2zBR94DZ73kvoJ/7DXd6mX5
mi8DGDK0GbJlx1RcojsmDesr1wKBgQDKz7mgmiCSqMVLNLz/2U64rP3VdQ+XhDnT
Yrx3uOczGc398jGXlQuRz60kV5b4M0sXb97z1/lLdIpy+jDs93BFo4wb8oRPEq+H
+UY2jArC9jJ+tlje13HM6pPL1AVqTjXHxzxWodL6SuFXwqVsLtlKlSLJeaNRSbWW
1MAqWFPGDwKBgEQ6YOIoknl6QMxsjxXciZw2AIrCdnx+es/vFqY2+asdeOWd2S/p
9efC0sx21bf46o6pO8g61iWzoTHZQGWy5hLDjYXZ0WIJ5QlcV7CboROBR+JSjcNC
AUiUeXVvrxuTxKbnlTxv0q01am8wxfhZGqel1Z0F/sd7VafBlj6p8QZJAoGBALry
A0+xArltbH9IW7cSnmfIvioWv4qQzaS2bLeG70bBUIn2yBPLxWBgqF7JhlW/Ika2
TjNDL36ILF6TlKm54/mtKadRQviIZtjVxAzfxcO0oRMADqdKvJGA4T+PbnZxJU3D
rzDD9e/VOiZlO4qfHJiNJAXHY+24HfSso33k8UOtAoGAEkfoaYQWlO49YivpwF3d
LxuuVBdCRYh90xpq3EAvct01USVItzdve/itNwRT9TxnAiPLClzElYupUYzSL18o
k0xb48idsCkPnRNFJcSBrreXEMeXb3NEZQtcaXERmqqQLod3fc9g1FODH8UmqFAo
lG32vFH+CdjqQwek+9KJCVY=
-----END PRIVATE KEY-----";

        #region Helper Methods

        [SetUp]
        public void SetUp()
        {
            // Generate a real RSA key pair for testing
            using var rsa = RSA.Create();
            rsa.KeySize = 2048;
            rsa.ExportParameters(true);
            
            // Build PEM formatted keys (simplified - in real tests you'd use proper PEM encoding)
            // For now, we'll use the test keys above or skip tests that need real keys
        }

        #endregion

        #region Encrypt Normal Cases

        [Test]
        public void Encrypt_DefaultParameters_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
            Assert.AreNotEqual(plainData, cipherData);
        }

        [Test]
        public void Encrypt_PKCS1Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test PKCS1 padding");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey, RSAEncryptionPadding.Pkcs1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_OAEPPadding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP padding");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey, RSAEncryptionPadding.OaepSHA1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_OAEPSHA256Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP SHA256 padding");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey, RSAEncryptionPadding.OaepSHA256);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_SmallData_ReturnsValidByteArray()
        {
            var plainData = new byte[] { 42 };
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_LargeData_ReturnsValidByteArray()
        {
            var plainData = new byte[1024];
            new Random().NextBytes(plainData);
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_SameData_MultipleEncryptions_ReturnsDifferentCipherText()
        {
            var plainData = Encoding.UTF8.GetBytes("Same data multiple times");
            var publicKey = GenerateTestPublicKey();

            var cipherData1 = RsaCryptoUtility.Encrypt(plainData, publicKey);
            var cipherData2 = RsaCryptoUtility.Encrypt(plainData, publicKey);

            Assert.AreNotEqual(cipherData1, cipherData2);
        }

        [Test]
        public void Encrypt_UnicodeText_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("你好，世界！こんにちは世界！🌍");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        #endregion

        #region Decrypt Normal Cases

        [Test]
        public void Decrypt_DefaultParameters_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2);

            Assert.AreEqual(plainData, decryptedData);
            CollectionAssert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void Decrypt_PKCS1Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test PKCS1 padding decryption");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1, RSAEncryptionPadding.Pkcs1);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2, RSAEncryptionPadding.Pkcs1);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void Decrypt_OAEPPadding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP padding decryption");
            var keyPair = GenerateTestKeyPair();
            
            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1, RSAEncryptionPadding.OaepSHA1);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2, RSAEncryptionPadding.OaepSHA1);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void Decrypt_OAEPSHA256Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP SHA256 padding decryption");
            
            var cipherData = RsaCryptoUtility.Encrypt(plainData, TestRsaPkcs8PublicKey, RSAEncryptionPadding.OaepSHA256);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, TestRsaPkcs8PrivateKey, RSAEncryptionPadding.OaepSHA256);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void Decrypt_LargeData_ReturnsOriginalPlainText()
        {
            var plainData = new byte[1024];
            new Random().NextBytes(plainData);
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_Success()
        {
            var plainData = Encoding.UTF8.GetBytes("Round trip test data");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2);

            Assert.AreEqual(plainData, decryptedData);
            CollectionAssert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void EncryptDecrypt_UnicodeText_RoundTrip_Success()
        {
            var plainData = Encoding.UTF8.GetBytes("你好，世界！こんにちは世界！🌍");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2);

            Assert.AreEqual(plainData, decryptedData);
        }

        #endregion

        #region Encrypt Exception Tests

        [Test]
        public void Encrypt_NullPublicKey_ThrowsArgumentNullException()
        {
            var plainData = Encoding.UTF8.GetBytes("Test data");

            Assert.Throws<ArgumentNullException>(() => RsaCryptoUtility.Encrypt(plainData, null!));
        }

        [Test]
        public void Encrypt_EmptyPublicKey_ThrowsArgumentNullException()
        {
            var plainData = Encoding.UTF8.GetBytes("Test data");

            Assert.Throws<ArgumentNullException>(() => RsaCryptoUtility.Encrypt(plainData, string.Empty));
        }

        [Test]
        public void Encrypt_NullPlainData_ReturnsNull()
        {
            var publicKey = GenerateTestPublicKey();

            var result = RsaCryptoUtility.Encrypt(null, publicKey);

            Assert.IsNull(result);
        }

        [Test]
        public void Encrypt_EmptyPlainData_ReturnsEmptyArray()
        {
            var plainData = Array.Empty<byte>();
            var publicKey = GenerateTestPublicKey();

            var result = RsaCryptoUtility.Encrypt(plainData, publicKey);

            Assert.IsNotNull(result);
            Assert.IsEmpty(result);
        }

        [Test]
        public void Encrypt_InvalidPublicKeyFormat_ThrowsException()
        {
            var plainData = Encoding.UTF8.GetBytes("Test data");
            const string invalidPublicKey = "INVALID_PUBLIC_KEY";

            Assert.Throws<FormatException>(() => RsaCryptoUtility.Encrypt(plainData, invalidPublicKey));
        }

        #endregion

        #region Decrypt Exception Tests

        [Test]
        public void Decrypt_NullPrivateKey_ThrowsArgumentNullException()
        {
            var cipherData = Encoding.UTF8.GetBytes("Encrypted data");

            Assert.Throws<ArgumentNullException>(() => RsaCryptoUtility.Decrypt(cipherData, null!));
        }

        [Test]
        public void Decrypt_EmptyPrivateKey_ThrowsArgumentNullException()
        {
            var cipherData = Encoding.UTF8.GetBytes("Encrypted data");

            Assert.Throws<ArgumentNullException>(() => RsaCryptoUtility.Decrypt(cipherData, string.Empty));
        }

        [Test]
        public void Decrypt_NullCipherData_ReturnsNull()
        {
            var privateKey = GenerateTestPrivateKey();

            var result = RsaCryptoUtility.Decrypt(null, privateKey);

            Assert.IsNull(result);
        }

        [Test]
        public void Decrypt_EmptyCipherData_ReturnsEmptyArray()
        {
            var cipherData = Array.Empty<byte>();
            var privateKey = GenerateTestPrivateKey();

            var result = RsaCryptoUtility.Decrypt(cipherData, privateKey);

            Assert.IsNotNull(result);
            Assert.IsEmpty(result);
        }

        [Test]
        public void Decrypt_InvalidPrivateKeyFormat_ThrowsException()
        {
            var cipherData = Encoding.UTF8.GetBytes("Encrypted data");
            const string invalidPrivateKey = "INVALID_PRIVATE_KEY";
            Assert.Throws<FormatException>(() => RsaCryptoUtility.Decrypt(cipherData, invalidPrivateKey));
        }

#if NETSTANDARD2_0_OR_GREATER
        [Test]
        public void Decrypt_WrongPrivateKey_DecryptionFails()
        {
            var plainData = Encoding.UTF8.GetBytes("Wrong key test");
            GenerateTestKeyPair();
            var keyPair2 = GenerateTestKeyPair();
            var keyPair3 = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair3.Item1);

            Assert.Throws<CryptographicUnexpectedOperationException>(() => RsaCryptoUtility.Decrypt(cipherData, keyPair2.Item2));
        }
#endif

        [Test]
        public void Decrypt_MismatchedPadding_ThrowsCryptographicException()
        {
            var plainData = Encoding.UTF8.GetBytes("Mismatched padding test");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1, RSAEncryptionPadding.Pkcs1);

            Assert.Throws<CryptographicException>(() => 
                RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2, RSAEncryptionPadding.OaepSHA1));
        }

        #endregion

        #region Different Key Sizes Tests

        [Test]
        public void Encrypt_1024BitKey_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("1024-bit key test");
            var keyPair = GenerateTestKeyPair(1024);

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_2048BitKey_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("2048-bit key test");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_4096BitKey_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("4096-bit key test");
            var keyPair = GenerateTestKeyPair(4096);

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void EncryptDecrypt_DifferentKeySizes_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Different key sizes test");

            var keyPair1024 = GenerateTestKeyPair(1024);
            var cipherData1024 = RsaCryptoUtility.Encrypt(plainData, keyPair1024.Item1);
            var decryptedData1024 = RsaCryptoUtility.Decrypt(cipherData1024, keyPair1024.Item2);
            Assert.AreEqual(plainData, decryptedData1024);

            var keyPair2048 = GenerateTestKeyPair();
            var cipherData2048 = RsaCryptoUtility.Encrypt(plainData, keyPair2048.Item1);
            var decryptedData2048 = RsaCryptoUtility.Decrypt(cipherData2048, keyPair2048.Item2);
            Assert.AreEqual(plainData, decryptedData2048);
        }

        #endregion

        #region Boundary and Special Cases Tests

        [Test]
        public void Encrypt_MaximumDataSize_ReturnsValidByteArray()
        {
            var keyPair = GenerateTestKeyPair();
            const int maxDataSize = 2048 / 8 - 11; // RSA-2048 with PKCS1 padding
            var plainData = new byte[maxDataSize];
            new Random().NextBytes(plainData);

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

#if !NETSTANDARD2_0_OR_GREATER
        [Test]
        public void Encrypt_TamperedCipherText_DecryptionFails()
        {
            var plainData = Encoding.UTF8.GetBytes("Tampered data test");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);
            if (cipherData == null)
                return;
            
            cipherData[0] ^= 0xFF;
            Assert.Throws<CryptographicUnexpectedOperationException>(() => RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2));
        }
#endif
        
#if NETSTANDARD2_0_OR_GREATER
        [Test]
        public void Encrypt_TruncatedCipherText_DecryptionFails()
        {
            var plainData = Encoding.UTF8.GetBytes("Truncated data test");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);
            if (cipherData == null)
                return;
            
            var truncatedData = new byte[cipherData.Length / 2];
            Array.Copy(cipherData, truncatedData, truncatedData.Length);

            Assert.Throws<CryptographicUnexpectedOperationException>(() => RsaCryptoUtility.Decrypt(truncatedData, keyPair.Item2));
        }
#endif

        #endregion

        #region Performance Tests

        [Test]
        public void Encrypt_PerformanceTest_CompletesInReasonableTime()
        {
            var plainData = new byte[1024];
            new Random().NextBytes(plainData);
            var keyPair = GenerateTestKeyPair();

            var startTime = DateTime.UtcNow;
            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);
            var endTime = DateTime.UtcNow;

            Assert.IsNotNull(cipherData);
            Assert.Less((endTime - startTime).TotalSeconds, 5);
        }

        [Test]
        public void Decrypt_PerformanceTest_CompletesInReasonableTime()
        {
            var plainData = new byte[1024];
            new Random().NextBytes(plainData);
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1);

            var startTime = DateTime.UtcNow;
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2);
            var endTime = DateTime.UtcNow;

            Assert.IsNotNull(decryptedData);
            Assert.Less((endTime - startTime).TotalSeconds, 5);
        }

        #endregion

        #region Helper Methods

        private static string GenerateTestPublicKey()
        {
            using var rsa = RSA.Create();
            rsa.KeySize = 2048;
            var parameters = rsa.ExportParameters(false);
            return RsaCryptoUtility.ToPemPublicKey(parameters);
        }

        private static string GenerateTestPrivateKey()
        {
            using var rsa = RSA.Create();
            rsa.KeySize = 2048;
            var parameters = rsa.ExportParameters(true);
            return RsaCryptoUtility.ToPemPrivateKey(parameters);
        }

        private static Tuple<string, string> GenerateTestKeyPair(int keySize = 2048)
        {
            using var rsa = RSA.Create();
            rsa.KeySize = keySize;
            var parameters = rsa.ExportParameters(true);
            var publicKey = RsaCryptoUtility.ToPemPublicKey(parameters);
            var privateKey = RsaCryptoUtility.ToPemPrivateKey(parameters);
            return new Tuple<string, string>(publicKey, privateKey);
        }

        #endregion
    }
}