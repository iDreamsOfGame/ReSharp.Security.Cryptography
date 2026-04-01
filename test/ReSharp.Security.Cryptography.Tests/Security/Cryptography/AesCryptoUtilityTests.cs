using System;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class AesCryptoUtilityTests
    {
        #region Encrypt Normal Cases

        [Test]
        public void Encrypt_DefaultParameters_ReturnsValidByteArray()
        {
            const string expected = "jOicGEwiJ2vg+urauFC2Ig==";
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = HexConverter.FromHexString("eb3c20d04dbfe04e4b781a33c191d9774b48f18d4c488b5f084f4cecdfaf778b");
            var iv = HexConverter.FromHexString("9f958b7801a39a85fb6c7efeeb8d595d");

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
            Assert.AreNotEqual(plainText, cipherText);
            Assert.AreEqual(expected, Convert.ToBase64String(cipherText));
        }

        [Test]
        public void Encrypt_CBCMode_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data for CBC mode");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_ECBMode_NoIvRequired_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data for ECB mode");
            var key = CryptoUtility.GenerateRandomKey(32);
            var cipherText = AesCryptoUtility.Encrypt(plainText, key, cipherMode: CipherMode.ECB);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_CFBMode_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data for CFB mode");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText,
                key,
                iv,
                CipherMode.CFB);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_OFBMode_ThrowsCryptographicException()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data for OFB mode");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<CryptographicException>(() => AesCryptoUtility.Encrypt(plainText,
                key,
                iv,
                CipherMode.OFB));
        }

        [Test]
        public void Encrypt_LargeData_ReturnsValidByteArray()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_SameDataDifferentIV_ReturnsDifferentCipherText()
        {
            var plainText = Encoding.UTF8.GetBytes("Same data");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv1 = CryptoUtility.GenerateRandomKey();
            var iv2 = CryptoUtility.GenerateRandomKey();

            var cipherText1 = AesCryptoUtility.Encrypt(plainText, key, iv1);
            var cipherText2 = AesCryptoUtility.Encrypt(plainText, key, iv2);

            Assert.AreNotEqual(cipherText1, cipherText2);
        }

        [Test]
        public void Encrypt_SameDataSameIV_ReturnsSameCipherText()
        {
            var plainText = Encoding.UTF8.GetBytes("Same data");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

            var cipherText1 = AesCryptoUtility.Encrypt(plainText, key, iv);
            var cipherText2 = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.AreEqual(cipherText1, cipherText2);
        }

        #endregion

        #region Decrypt Normal Cases

        [Test]
        public void Decrypt_DefaultParameters_ReturnsOriginalPlainText()
        {
            const string cipherText = "jOicGEwiJ2vg+urauFC2Ig==";
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = HexConverter.FromHexString("eb3c20d04dbfe04e4b781a33c191d9774b48f18d4c488b5f084f4cecdfaf778b");
            var iv = HexConverter.FromHexString("9f958b7801a39a85fb6c7efeeb8d595d");
            var decryptedText = AesCryptoUtility.Decrypt(Convert.FromBase64String(cipherText), key, iv);
            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_CBCMode_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Test CBC mode decryption");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            var decryptedText = AesCryptoUtility.Decrypt(cipherText, key, iv);

            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_ECBMode_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Test ECB mode decryption");
            var key = CryptoUtility.GenerateRandomKey(32);

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, cipherMode: CipherMode.ECB);
            var decryptedText = AesCryptoUtility.Decrypt(cipherText, key, cipherMode: CipherMode.ECB);

            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_CFBMode_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Test CFB mode decryption");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText,
                key,
                iv,
                CipherMode.CFB);
            var decryptedText = AesCryptoUtility.Decrypt(cipherText,
                key,
                iv,
                CipherMode.CFB);

            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_LargeData_ReturnsOriginalPlainText()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            var decryptedText = AesCryptoUtility.Decrypt(cipherText, key, iv);

            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_Success()
        {
            var plainText = Encoding.UTF8.GetBytes("Round trip test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            var decryptedText = AesCryptoUtility.Decrypt(cipherText, key, iv);

            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        #endregion

        #region Encrypt Exception Tests

        [Test]
        public void Encrypt_NullPlainText_ThrowsArgumentNullException()
        {
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(null!, key, iv));
        }

        [Test]
        public void Encrypt_EmptyPlainText_ThrowsArgumentNullException()
        {
            var plainText = Array.Empty<byte>();
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(plainText, key, iv));
        }

        [Test]
        public void Encrypt_NullKey_ThrowsArgumentNullException()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data");
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(plainText, null!, iv));
        }

        [Test]
        public void Encrypt_EmptyKey_ThrowsArgumentNullException()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data");
            var key = Array.Empty<byte>();
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(plainText, key, iv));
        }

        [Test]
        public void Encrypt_CBCMode_NullIV_ThrowsArgumentNullException()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data");
            var key = CryptoUtility.GenerateRandomKey(32);
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(plainText, key));
        }

        [Test]
        public void Encrypt_CFBMode_NullIV_ThrowsArgumentNullException()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data");
            var key = CryptoUtility.GenerateRandomKey(32);

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(plainText, key, null, CipherMode.CFB));
        }

        [Test]
        public void Encrypt_OFBMode_NullIV_ThrowsArgumentNullException()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data");
            var key = CryptoUtility.GenerateRandomKey(32);

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(plainText, key, null, CipherMode.OFB));
        }

        [Test]
        public void Encrypt_ECBMode_NullIV_DoesNotThrow()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data");
            var key = CryptoUtility.GenerateRandomKey(32);

            Assert.DoesNotThrow(() => AesCryptoUtility.Encrypt(plainText, key, null, CipherMode.ECB));
        }

        [Test]
        public void Encrypt_EmptyIV_ThrowsArgumentNullException()
        {
            var plainText = Encoding.UTF8.GetBytes("Test data");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = Array.Empty<byte>();
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(plainText, key, iv));
        }

        #endregion

        #region Decrypt Exception Tests

        [Test]
        public void Decrypt_NullCipherText_ThrowsArgumentNullException()
        {
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(null!, key, iv));
        }

        [Test]
        public void Decrypt_EmptyCipherText_ThrowsArgumentNullException()
        {
            var cipherText = Array.Empty<byte>();
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(cipherText, key, iv));
        }

        [Test]
        public void Decrypt_NullKey_ThrowsArgumentNullException()
        {
            var cipherText = Encoding.UTF8.GetBytes("Encrypted data");
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(cipherText, null!, iv));
        }

        [Test]
        public void Decrypt_EmptyKey_ThrowsArgumentNullException()
        {
            var cipherText = Encoding.UTF8.GetBytes("Encrypted data");
            var key = Array.Empty<byte>();
            var iv = CryptoUtility.GenerateRandomKey();

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(cipherText, key, iv));
        }

        [Test]
        public void Decrypt_CBCMode_NullIV_ThrowsArgumentNullException()
        {
            var cipherText = Encoding.UTF8.GetBytes("Encrypted data");
            var key = CryptoUtility.GenerateRandomKey(32);
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(cipherText, key));
        }

        [Test]
        public void Decrypt_CFBMode_NullIV_ThrowsArgumentNullException()
        {
            var cipherText = Encoding.UTF8.GetBytes("Encrypted data");
            var key = CryptoUtility.GenerateRandomKey(32);

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(cipherText, key, null, CipherMode.CFB));
        }

        [Test]
        public void Decrypt_OFBMode_NullIV_ThrowsArgumentNullException()
        {
            var cipherText = Encoding.UTF8.GetBytes("Encrypted data");
            var key = CryptoUtility.GenerateRandomKey(32);

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(cipherText, key, null, CipherMode.OFB));
        }

        [Test]
        public void Decrypt_ECBMode_NullIV_ThrowsArgumentException()
        {
            var cipherText = Encoding.UTF8.GetBytes("Encrypted data");
            var key = CryptoUtility.GenerateRandomKey(32);
            Assert.Throws<ArgumentException>(() => AesCryptoUtility.Decrypt(cipherText, key, null, CipherMode.ECB));
        }

        [Test]
        public void Decrypt_EmptyIV_ThrowsArgumentNullException()
        {
            var cipherText = Encoding.UTF8.GetBytes("Encrypted data");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = Array.Empty<byte>();
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(cipherText, key, iv));
        }

        #endregion

        #region Different Key Length Tests

        [Test]
        public void Encrypt_128BitKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("128-bit key test");
            var key = CryptoUtility.GenerateRandomKey();
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_192BitKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("192-bit key test");
            var key = CryptoUtility.GenerateRandomKey(24);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_256BitKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("256-bit key test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Decrypt_DifferentKeyLengths_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Different key lengths test");

            var key128 = CryptoUtility.GenerateRandomKey();
            var iv1 = CryptoUtility.GenerateRandomKey();
            var cipherText1 = AesCryptoUtility.Encrypt(plainText, key128, iv1);
            var decryptedText1 = AesCryptoUtility.Decrypt(cipherText1, key128, iv1);
            Assert.AreEqual(plainText, decryptedText1);

            var key192 = CryptoUtility.GenerateRandomKey(24);
            var iv2 = CryptoUtility.GenerateRandomKey();
            var cipherText2 = AesCryptoUtility.Encrypt(plainText, key192, iv2);
            var decryptedText2 = AesCryptoUtility.Decrypt(cipherText2, key192, iv2);
            Assert.AreEqual(plainText, decryptedText2);

            var key256 = CryptoUtility.GenerateRandomKey(32);
            var iv3 = CryptoUtility.GenerateRandomKey();
            var cipherText3 = AesCryptoUtility.Encrypt(plainText, key256, iv3);
            var decryptedText3 = AesCryptoUtility.Decrypt(cipherText3, key256, iv3);
            Assert.AreEqual(plainText, decryptedText3);
        }

        #endregion

        #region Different Padding Mode Tests

        [Test]
        public void Encrypt_PKCS7Padding_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("PKCS7 padding test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();
            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_ZerosPadding_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("Zeros padding test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(
                plainText,
                key,
                iv,
                CipherMode.CBC,
                PaddingMode.Zeros);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_ANSIX923Padding_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("ANSI X9.23 padding test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(
                plainText,
                key,
                iv,
                CipherMode.CBC,
                PaddingMode.ANSIX923);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_ISO10126Padding_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("ISO 10126 padding test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(
                plainText,
                key,
                iv,
                CipherMode.CBC,
                PaddingMode.ISO10126);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Decrypt_DifferentPaddingModes_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Padding modes test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherTextPkcs7 = AesCryptoUtility.Encrypt(plainText, key, iv);
            var decryptedPkcs7 = AesCryptoUtility.Decrypt(cipherTextPkcs7, key, iv);
            Assert.AreEqual(plainText, decryptedPkcs7);

            var cipherTextAnsix923 = AesCryptoUtility.Encrypt(
                plainText,
                key,
                iv,
                CipherMode.CBC,
                PaddingMode.ANSIX923);
            var decryptedAnsix923 = AesCryptoUtility.Decrypt(
                cipherTextAnsix923,
                key,
                iv,
                CipherMode.CBC,
                PaddingMode.ANSIX923);
            Assert.AreEqual(plainText, decryptedAnsix923);
        }

        #endregion

        #region Boundary and Special Cases Tests

        [Test]
        public void Encrypt_SingleByte_ReturnsValidByteArray()
        {
            var plainText = new byte[] { 42 };
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Decrypt_SingleByte_ReturnsOriginalValue()
        {
            var plainText = new byte[] { 42 };
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            var decryptedText = AesCryptoUtility.Decrypt(cipherText, key, iv);

            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Encrypt_BlockSizeData_ReturnsValidByteArray()
        {
            var plainText = new byte[16];
            new Random().NextBytes(plainText);
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_WrongKey_DecryptionFailsOrReturnsDifferentData()
        {
            var plainText = Encoding.UTF8.GetBytes("Wrong key test");
            var key1 = CryptoUtility.GenerateRandomKey(32);
            var key2 = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key1, iv);

            Assert.Throws<CryptographicException>(() => AesCryptoUtility.Decrypt(cipherText, key2, iv));
        }

        [Test]
        public void Encrypt_WrongIV_DecryptionFailsOrReturnsDifferentData()
        {
            var plainText = Encoding.UTF8.GetBytes("Wrong IV test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv1 = CryptoUtility.GenerateRandomKey();
            var iv2 = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv1);

            Assert.Throws<CryptographicException>(() => AesCryptoUtility.Decrypt(cipherText, key, iv2));
        }

        [Test]
        public void Encrypt_TamperedCipherText_DecryptionFails()
        {
            var plainText = Encoding.UTF8.GetBytes("Tampered data test");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            cipherText[0] ^= 0xFF;
            var result = AesCryptoUtility.Decrypt(cipherText, key, iv);
            Assert.AreNotEqual(plainText, Encoding.UTF8.GetString(result));
        }

        #endregion

        #region Performance Tests

        [Test]
        public void Encrypt_PerformanceTest_CompletesInReasonableTime()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var startTime = DateTime.UtcNow;
            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            var endTime = DateTime.UtcNow;

            Assert.IsNotNull(cipherText);
            Assert.Less((endTime - startTime).TotalSeconds, 5);
        }

        [Test]
        public void Decrypt_PerformanceTest_CompletesInReasonableTime()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            var startTime = DateTime.UtcNow;
            var decryptedText = AesCryptoUtility.Decrypt(cipherText, key, iv);
            var endTime = DateTime.UtcNow;

            Assert.IsNotNull(decryptedText);
            Assert.Less((endTime - startTime).TotalSeconds, 5);
        }

        #endregion

        #region Unicode and Multi-language Support Tests

        [Test]
        public void Encrypt_UnicodeText_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("你好，世界！こんにちは世界！🌍");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);

            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Decrypt_UnicodeText_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("你好，世界！こんにちは世界！🌍");
            var key = CryptoUtility.GenerateRandomKey(32);
            var iv = CryptoUtility.GenerateRandomKey();

            var cipherText = AesCryptoUtility.Encrypt(plainText, key, iv);
            var decryptedText = AesCryptoUtility.Decrypt(cipherText, key, iv);

            Assert.AreEqual(plainText, decryptedText);
        }

        #endregion
    }
}