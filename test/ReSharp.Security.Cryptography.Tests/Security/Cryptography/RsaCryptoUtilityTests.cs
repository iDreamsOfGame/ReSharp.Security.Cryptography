using System;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

// ReSharper disable AssignNullToNotNullAttribute

namespace ReSharp.Security.Cryptography.Tests
{
    public class RsaCryptoUtilityTests
    {
        private const string TestRsaPkcs8PublicKey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFDPI8qxP8orEHrd4dXF
fgQhtu7xZMU+XZKz5ZXiGfHxaBsijEZ5jJ/g157ppag/DXJUC8GfbUy3Cx8cqJMw
nIIwZNcjVl5bI9zzK0NTo0WSPsL4bujeF8GWRwfvlQDRn4VKNsRszaedB1tVkd83
UxSyaCdm2JKJ6NzWYUZqgZ6cvxbVq527VxpzfE1cBerG5rfeGwkyha7BL34gpBSg
P0bssYydOeI8hhIxDuICumTYQz9OZp86UTQQAtXnl6k/WvFAcboFZSZ/vWsul+O2
9mKuNi3cZ8rZZLwmpsueVnMnCORElf66Fcxb5AVFWt+rolSU/Pmcc4TMfMiVS+Pk
CQIDAQAB
-----END PUBLIC KEY-----";

        private const string TestRsaPkcs8PrivateKey = @"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEUM8jyrE/yisQ
et3h1cV+BCG27vFkxT5dkrPlleIZ8fFoGyKMRnmMn+DXnumlqD8NclQLwZ9tTLcL
HxyokzCcgjBk1yNWXlsj3PMrQ1OjRZI+wvhu6N4XwZZHB++VANGfhUo2xGzNp50H
W1WR3zdTFLJoJ2bYkono3NZhRmqBnpy/FtWrnbtXGnN8TVwF6sbmt94bCTKFrsEv
fiCkFKA/RuyxjJ054jyGEjEO4gK6ZNhDP05mnzpRNBAC1eeXqT9a8UBxugVlJn+9
ay6X47b2Yq42LdxnytlkvCamy55WcycI5ESV/roVzFvkBUVa36uiVJT8+ZxzhMx8
yJVL4+QJAgMBAAECggEAGsxmLl5bule8b7Q6CDtQiY6CVLDC+ozTYd4mGRPQCNcm
a13y5h+ztX7YqE582hyAuPLvpqgwfXDgts+xL5DiLKc3+HgGzqI0Qk3F0xTOfMYB
O/iNBcTblnYab8lVSuuQ8fv1wMqpCJzWGnw9Dtvf90MmxIGGcE92rHdC+4XrgZR6
KRtPdP1AVIN7Fdu1HSjJFw37JkFIvRXv3tar7Amzuzj0yJfKmgMsc0+G2bJB4OMU
OfVZE/HHLG0sU/L8TIdYbvuUN4PriPdTBUmK6JavQLKvlWFDyvEFamLP2E/vDlLY
6od/bf+I+EAOgZoZqYHYZBLiVNFILawyfnh4s4UnJQKBgQDzyGJQcXEtVES4GMBN
KInppaReA5sQa2xAKDokeVbL0cw30+kJhfw0n+DyMB4oF2Ei4g7FrYqeV5RpMsaB
tLzO1kngg35AKGE3wQAadN+geNuikZmh7HecFwI36P42WDMLb1ua7sw7uYgwUFFj
4J4X0kCf+pJCePtC5BGYJCUIPQKBgQDOJ3HwFv4f1Z0e8GinKqSGd+wvJ0chdI7A
N6yjX+0+r4v5xvsKlWh/FSEb7KlwoIpcpklOiE9NmVZf76n6Zk6KiNElvRUskEC0
6g11PTtrj1l3raA0yAit24mUkifvQ8ut71qM3b8J7G/Qyk4J0nZ2IkSFH/Ig/EAm
D3guMe37vQKBgDytS4sqMTlPGCuaPYL27Byzlc2wqA/WLQNq/83ERc5FUcczf3VX
XAbdJGgjgd4Is6yzB2o8X5w5wD7O3Im8KqJww8KV9/6QDmKKLzRmkqKmckRsaQjc
iojXUT4JR/zOxyW5edt+RGc5LqSX2So65h6Xvm4TOARDiIaFrbtog68hAoGAeagX
efrnnru9zCtNZxEoJF6S18TTGjAhqddxHryWUf7gmNdPAJDpKM28SzFfUKK85C4R
ZrHUMtQBf/38DlPfl6tj2WR7IWBDfz/8DyrCbRgcUR76Qwuk64x55V5XCMC2av+s
LSMTAPUxi0JHyU4VMGPKkdEnX0XdSVipsIEwkvUCgYEAjqHd4AGWxdNfJTjpXMvl
Uwb8r+LrSZq+2umcFGd6SRHwD/V7kNvucKFSsbuVk2aUF0ae5X4VW6KuGisB8Ivr
M0NlrU9sArcB8mmO/q8kMR1UaYxIw4S+RCmPi7wj4Txhh+p0sfvTFiNNht2J1zQ/
o6343nhCZJu0L8MT6hw6faA=
-----END PRIVATE KEY-----";

        #region Helper Methods

        [SetUp]
        public void SetUp()
        {
            using var rsa = RSA.Create();
            rsa.KeySize = 2048;
            rsa.ExportParameters(true);
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
        public void Encrypt_OAEPSHA384Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP SHA384 padding");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainData, publicKey, RSAEncryptionPadding.OaepSHA384);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_OAEPSHA512Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP SHA512 padding");
            var cipherData = RsaCryptoUtility.Encrypt(plainData, TestRsaPkcs8PublicKey, RSAEncryptionPadding.OaepSHA512);

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
        public void Decrypt_OAEPSHA384Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP SHA384 padding decryption");
            var keyPair = GenerateTestKeyPair();
            
            var cipherData = RsaCryptoUtility.Encrypt(plainData, keyPair.Item1, RSAEncryptionPadding.OaepSHA384);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, keyPair.Item2, RSAEncryptionPadding.OaepSHA384);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void Decrypt_OAEPSHA512Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test OAEP SHA512 padding decryption");
            
            var cipherData = RsaCryptoUtility.Encrypt(plainData, TestRsaPkcs8PublicKey, RSAEncryptionPadding.OaepSHA512);
            var decryptedData = RsaCryptoUtility.Decrypt(cipherData, TestRsaPkcs8PrivateKey, RSAEncryptionPadding.OaepSHA512);

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

        #region String Encrypt Tests

        [Test]
        public void Encrypt_String_DefaultParameters_ReturnsValidByteArray()
        {
            var plainText = "Hello, World!";
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainText, publicKey);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_String_UTF8Encoding_ReturnsValidByteArray()
        {
            var plainText = "Hello, 世界！";
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainText, publicKey, Encoding.UTF8);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_String_UnicodeEncoding_ReturnsValidByteArray()
        {
            var plainText = "你好，世界！";
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.Encrypt(plainText, publicKey, Encoding.Unicode);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_String_NullPlainText_ThrowsArgumentNullException()
        {
            var publicKey = GenerateTestPublicKey();

            Assert.Throws<ArgumentNullException>(() => RsaCryptoUtility.Encrypt((string)null, publicKey));
        }

        [Test]
        public void Encrypt_String_EmptyPlainText_ThrowsArgumentNullException()
        {
            var publicKey = GenerateTestPublicKey();

            Assert.Throws<ArgumentNullException>(() => RsaCryptoUtility.Encrypt("", publicKey));
        }

        #endregion

        #region EncryptToHexString Tests

        [Test]
        public void EncrpytToHexString_ByteArray_ReturnsValidHexString()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var publicKey = GenerateTestPublicKey();

            var hexString = RsaCryptoUtility.EncrpytToHexString(plainData, publicKey);

            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
        }

        [Test]
        public void EncrpytToHexString_ByteArray_LowerCase_ReturnsValidHexString()
        {
            var plainData = Encoding.UTF8.GetBytes("Test lowercase hex");
            var publicKey = GenerateTestPublicKey();

            var hexString = RsaCryptoUtility.EncrpytToHexString(plainData, publicKey, false);

            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
            Assert.AreEqual(hexString, hexString.ToLower());
        }

        [Test]
        public void EncrpytToHexString_String_ReturnsValidHexString()
        {
            var plainText = "Hello, World!";
            var publicKey = GenerateTestPublicKey();

            var hexString = RsaCryptoUtility.EncrpytToHexString(plainText, publicKey);

            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
        }

        [Test]
        public void EncrpytToHexString_String_UTF8Encoding_ReturnsValidHexString()
        {
            var plainText = "你好，世界！";
            var publicKey = GenerateTestPublicKey();

            var hexString = RsaCryptoUtility.EncrpytToHexString(plainText, publicKey, Encoding.UTF8);

            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
        }

        #endregion

        #region EncryptToBase64String Tests

        [Test]
        public void EncrpytToBase64String_ByteArray_ReturnsValidBase64String()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var publicKey = GenerateTestPublicKey();

            var base64String = RsaCryptoUtility.EncrpytToBase64String(plainData, publicKey);

            Assert.IsNotNull(base64String);
            Assert.Greater(base64String.Length, 0);
        }

        [Test]
        public void EncrpytToBase64String_String_ReturnsValidBase64String()
        {
            var plainText = "Hello, World!";
            var publicKey = GenerateTestPublicKey();

            var base64String = RsaCryptoUtility.EncrpytToBase64String(plainText, publicKey);

            Assert.IsNotNull(base64String);
            Assert.Greater(base64String.Length, 0);
        }

        [Test]
        public void EncrpytToBase64String_String_UnicodeText_ReturnsValidBase64String()
        {
            var plainText = "你好，世界！";
            var publicKey = GenerateTestPublicKey();

            var base64String = RsaCryptoUtility.EncrpytToBase64String(plainText, publicKey, Encoding.UTF8);

            Assert.IsNotNull(base64String);
            Assert.Greater(base64String.Length, 0);
        }

        #endregion

        #region Encrypt Exception Cases

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

            var result = RsaCryptoUtility.Encrypt((byte[])null, publicKey);

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

        #region Decrypt Exception Cases

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

        #region Internal Method Tests - .NET Implementation

        [Test]
        public void InternalEncryptWithDotNet_PKCS1Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test .NET encrypt");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.InternalEncryptWithDotNet(plainData, publicKey, RSAEncryptionPadding.Pkcs1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void InternalEncryptWithDotNet_OAEPSHA1Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test .NET OAEP SHA1 encrypt");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.InternalEncryptWithDotNet(plainData, publicKey, RSAEncryptionPadding.OaepSHA1);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void InternalDecryptWithDotNet_PKCS1Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test .NET decrypt");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.InternalEncryptWithDotNet(plainData, keyPair.Item1, RSAEncryptionPadding.Pkcs1);
            var decryptedData = RsaCryptoUtility.InternalDecryptWithDotNet(cipherData, keyPair.Item2, RSAEncryptionPadding.Pkcs1);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void InternalDecryptWithDotNet_OAEPSHA1Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test .NET OAEP SHA1 decrypt");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.InternalEncryptWithDotNet(plainData, keyPair.Item1, RSAEncryptionPadding.OaepSHA1);
            var decryptedData = RsaCryptoUtility.InternalDecryptWithDotNet(cipherData, keyPair.Item2, RSAEncryptionPadding.OaepSHA1);

            Assert.AreEqual(plainData, decryptedData);
        }

        #endregion

        #region Internal Method Tests - BouncyCastle Implementation

        [Test]
        public void InternalEncryptWithBouncyCastle_OAEPSHA256Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test BC OAEP SHA256 encrypt");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.InternalEncryptWithBouncyCastle(plainData, publicKey, RSAEncryptionPadding.OaepSHA256);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void InternalEncryptWithBouncyCastle_OAEPSHA384Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test BC OAEP SHA384 encrypt");
            var publicKey = GenerateTestPublicKey();

            var cipherData = RsaCryptoUtility.InternalEncryptWithBouncyCastle(plainData, publicKey, RSAEncryptionPadding.OaepSHA384);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void InternalEncryptWithBouncyCastle_OAEPSHA512Padding_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Test BC OAEP SHA512 encrypt");
            var cipherData = RsaCryptoUtility.InternalEncryptWithBouncyCastle(plainData, TestRsaPkcs8PublicKey, RSAEncryptionPadding.OaepSHA512);

            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void InternalDecryptWithBouncyCastle_OAEPSHA256Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test BC OAEP SHA256 decrypt");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.InternalEncryptWithBouncyCastle(plainData, keyPair.Item1, RSAEncryptionPadding.OaepSHA256);
            var decryptedData = RsaCryptoUtility.InternalDecryptWithBouncyCastle(cipherData, keyPair.Item2, RSAEncryptionPadding.OaepSHA256);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void InternalDecryptWithBouncyCastle_OAEPSHA384Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test BC OAEP SHA384 decrypt");
            var keyPair = GenerateTestKeyPair();

            var cipherData = RsaCryptoUtility.InternalEncryptWithBouncyCastle(plainData, keyPair.Item1, RSAEncryptionPadding.OaepSHA384);
            var decryptedData = RsaCryptoUtility.InternalDecryptWithBouncyCastle(cipherData, keyPair.Item2, RSAEncryptionPadding.OaepSHA384);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void InternalDecryptWithBouncyCastle_OAEPSHA512Padding_ReturnsOriginalPlainText()
        {
            var plainData = Encoding.UTF8.GetBytes("Test BC OAEP SHA512 decrypt");
            var cipherData = RsaCryptoUtility.InternalEncryptWithBouncyCastle(plainData, TestRsaPkcs8PublicKey, RSAEncryptionPadding.OaepSHA512);
            var decryptedData = RsaCryptoUtility.InternalDecryptWithBouncyCastle(cipherData, TestRsaPkcs8PrivateKey, RSAEncryptionPadding.OaepSHA512);

            Assert.AreEqual(plainData, decryptedData);
        }

        [Test]
        public void InternalEncryptWithBouncyCastle_InvalidPublicKey_ThrowsFormatException()
        {
            var plainData = Encoding.UTF8.GetBytes("Test invalid BC key");
            const string invalidPublicKey = "INVALID_KEY";

            Assert.Throws<FormatException>(() => 
                RsaCryptoUtility.InternalEncryptWithBouncyCastle(plainData, invalidPublicKey, RSAEncryptionPadding.OaepSHA256));
        }

        [Test]
        public void InternalDecryptWithBouncyCastle_InvalidPrivateKey_ThrowsFormatException()
        {
            var cipherData = Encoding.UTF8.GetBytes("Test invalid BC key");
            const string invalidPrivateKey = "INVALID_KEY";

            Assert.Throws<FormatException>(() => 
                RsaCryptoUtility.InternalDecryptWithBouncyCastle(cipherData, invalidPrivateKey, RSAEncryptionPadding.OaepSHA256));
        }

        #endregion

        #region PEM Conversion Tests

        [Test]
        public void ToPemPublicKey_ValidParameters_ReturnsValidPemFormat()
        {
            using var rsa = RSA.Create();
            rsa.KeySize = 2048;
            var parameters = rsa.ExportParameters(false);

            var pemPublicKey = RsaCryptoUtility.ToPemPublicKey(parameters);

            Assert.IsNotNull(pemPublicKey);
            StringAssert.StartsWith("-----BEGIN", pemPublicKey);
            StringAssert.Contains("PUBLIC KEY-----", pemPublicKey);
        }

        [Test]
        public void ToPemPrivateKey_ValidParameters_ReturnsValidPemFormat()
        {
            using var rsa = RSA.Create();
            rsa.KeySize = 2048;
            var parameters = rsa.ExportParameters(true);

            var pemPrivateKey = RsaCryptoUtility.ToPemPrivateKey(parameters);

            Assert.IsNotNull(pemPrivateKey);
            StringAssert.StartsWith("-----BEGIN", pemPrivateKey);
            StringAssert.Contains("PRIVATE KEY-----", pemPrivateKey);
        }

        [Test]
        public void FromPemPublicKey_ValidPem_ReturnsValidRSAParameters()
        {
            var publicKey = GenerateTestPublicKey();

            var rsaParameters = RsaCryptoUtility.FromPemPublicKey(publicKey);

            Assert.IsNotNull(rsaParameters.Modulus);
            Assert.IsNotNull(rsaParameters.Exponent);
        }

        [Test]
        public void FromPemPrivateKey_ValidPem_ReturnsValidRSAParameters()
        {
            var privateKey = GenerateTestPrivateKey();

            var rsaParameters = RsaCryptoUtility.FromPemPrivateKey(privateKey);

            Assert.IsNotNull(rsaParameters.Modulus);
            Assert.IsNotNull(rsaParameters.Exponent);
            Assert.IsNotNull(rsaParameters.D);
        }

        [Test]
        public void FromPemPublicKey_InvalidPem_ThrowsFormatException()
        {
            const string invalidPublicKey = "INVALID_PEM_KEY";

            Assert.Throws<FormatException>(() => RsaCryptoUtility.FromPemPublicKey(invalidPublicKey));
        }

        [Test]
        public void FromPemPrivateKey_InvalidPem_ThrowsFormatException()
        {
            const string invalidPrivateKey = "INVALID_PEM_KEY";

            Assert.Throws<FormatException>(() => RsaCryptoUtility.FromPemPrivateKey(invalidPrivateKey));
        }

        [Test]
        public void PemConversion_RoundTrip_Success()
        {
            using var rsa = RSA.Create();
            rsa.KeySize = 2048;
            var originalParameters = rsa.ExportParameters(true);

            var pemPublicKey = RsaCryptoUtility.ToPemPublicKey(originalParameters);
            var pemPrivateKey = RsaCryptoUtility.ToPemPrivateKey(originalParameters);

            var importedPublicParameters = RsaCryptoUtility.FromPemPublicKey(pemPublicKey);
            var importedPrivateParameters = RsaCryptoUtility.FromPemPrivateKey(pemPrivateKey);

            CollectionAssert.AreEqual(originalParameters.Modulus, importedPublicParameters.Modulus);
            CollectionAssert.AreEqual(originalParameters.Exponent, importedPublicParameters.Exponent);
            CollectionAssert.AreEqual(originalParameters.Modulus, importedPrivateParameters.Modulus);
            CollectionAssert.AreEqual(originalParameters.Exponent, importedPrivateParameters.Exponent);
            CollectionAssert.AreEqual(originalParameters.D, importedPrivateParameters.D);
        }

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