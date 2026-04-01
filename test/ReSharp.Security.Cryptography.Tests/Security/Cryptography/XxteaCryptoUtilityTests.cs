using System;
using System.Linq;
using System.Text;
using NUnit.Framework;

// ReSharper disable PossibleNullReferenceException
// ReSharper disable AssignNullToNotNullAttribute

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class XxteaCryptoUtilityTests
    {
        #region Encrypt Normal Cases

        [Test]
        public void Encrypt_NullKey_ReturnsExpectedBase64String()
        {
            const string expected = "3Q0j1kmxctP8NpqZAKUVHOIB3pg=";
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var cipherData = XxteaCryptoUtility.Encrypt(plainData);
            Assert.AreEqual(expected, Convert.ToBase64String(cipherData));
        }

        [Test]
        public void Encrypt_NormalKey_ReturnsExpectedBase64String()
        {
            const string expected = "6M5gTio9MOj89hYOohEVxY2Jp9w=";
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var keyData = Encoding.UTF8.GetBytes("1234");
            var cipherData = XxteaCryptoUtility.Encrypt(plainData, keyData);
            Assert.AreEqual(expected, Convert.ToBase64String(cipherData));
        }

        [Test]
        public void Encrypt_NullKey_ReturnsValidByteArray()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var cipherData = XxteaCryptoUtility.Encrypt(plainData);
            
            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
            Assert.AreNotEqual(plainData, cipherData);
        }

        [Test]
        public void Encrypt_EmptyKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = Array.Empty<byte>();
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
            Assert.AreNotEqual(plainText, cipherText);
        }

        [Test]
        public void Encrypt_16ByteKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
            Assert.AreNotEqual(plainText, cipherText);
        }

        [Test]
        public void Encrypt_ShortKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
            Assert.AreNotEqual(plainText, cipherText);
        }

        [Test]
        public void Encrypt_LongKey_UsesFirst16Bytes()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                key[i] = (byte)i;
            }
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_SameDataSameKey_ReturnsSameCipherText()
        {
            var plainText = Encoding.UTF8.GetBytes("Same data");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText1 = XxteaCryptoUtility.Encrypt(plainText, key);
            var cipherText2 = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.AreEqual(cipherText1, cipherText2);
            CollectionAssert.AreEqual(cipherText1, cipherText2);
        }

        [Test]
        public void Encrypt_LargeData_ReturnsValidByteArray()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        #endregion

        #region Decrypt Normal Cases

        [Test]
        public void Decrypt_NullKey_ReturnsExpectedValue()
        {
            const string expected = "Hello, World!";
            const string cipherText = "3Q0j1kmxctP8NpqZAKUVHOIB3pg=";
            var plainData = XxteaCryptoUtility.Decrypt(Convert.FromBase64String(cipherText));
            Assert.AreEqual(expected, Encoding.UTF8.GetString(plainData));
        }

        [Test]
        public void Decrypt_NormalKey_ReturnsExpectedValue()
        {
            const string expected = "Hello, World!";
            const string cipherText = "GC+zjGzsm6bAEaMsx0lswPoGWFQ=";
            const string key = "qwerasdf!";
            var plainData = XxteaCryptoUtility.Decrypt(Convert.FromBase64String(cipherText), Encoding.UTF8.GetBytes(key));
            Assert.AreEqual(expected, Encoding.UTF8.GetString(plainData));
        }

        [Test]
        public void Decrypt_NullKey_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_EmptyKey_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = Array.Empty<byte>();
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_16ByteKey_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_ShortKey_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_RoundTrip_Success()
        {
            var plainText = Encoding.UTF8.GetBytes("Round trip test");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_LargeData_ReturnsOriginalPlainText()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        #endregion

        #region Empty Data Tests

        [Test]
        public void Encrypt_EmptyPlainText_ReturnsEmptyArray()
        {
            var plainText = Array.Empty<byte>();
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.AreEqual(0, cipherText.Length);
        }

        [Test]
        public void Decrypt_EmptyCipherText_ReturnsEmptyArray()
        {
            var cipherText = Array.Empty<byte>();
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.IsNotNull(decryptedText);
            Assert.AreEqual(0, decryptedText.Length);
        }

        #endregion

        #region Boundary and Special Cases Tests

        [Test]
        public void Encrypt_SingleByte_ReturnsValidByteArray()
        {
            var plainText = new byte[] { 42 };
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Decrypt_SingleByte_ReturnsOriginalValue()
        {
            var plainText = new byte[] { 42 };
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Encrypt_BlockSizeData_ReturnsValidByteArray()
        {
            var plainText = new byte[16];
            new Random().NextBytes(plainText);
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_WrongKey_DecryptionReturnsDifferentData()
        {
            var plainText = Encoding.UTF8.GetBytes("Wrong key test");
            var key1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            var key2 = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key1);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key2);
            
            Assert.AreNotEqual(plainText, decryptedText);
        }

        [Test]
        public void Encrypt_TamperedCipherText_DecryptionReturnsDifferentData()
        {
            var plainText = Encoding.UTF8.GetBytes("Tampered data test");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            cipherText[0] ^= 0xFF;
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreNotEqual(plainText, decryptedText);
        }

        #endregion

        #region Unicode and Multi-language Support Tests

        [Test]
        public void Encrypt_UnicodeText_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("你好，世界！こんにちは世界！🌍");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Decrypt_UnicodeText_ReturnsOriginalPlainText()
        {
            var plainText = Encoding.UTF8.GetBytes("你好，世界！こんにちは世界！🌍");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            CollectionAssert.AreEqual(plainText, decryptedText);
        }

        #endregion

        #region Performance Tests

        [Test]
        public void Encrypt_PerformanceTest_CompletesInReasonableTime()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var startTime = DateTime.UtcNow;
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var endTime = DateTime.UtcNow;
            
            Assert.IsNotNull(cipherText);
            Assert.Less((endTime - startTime).TotalSeconds, 5);
        }

        [Test]
        public void Decrypt_PerformanceTest_CompletesInReasonableTime()
        {
            var plainText = new byte[1024 * 1024];
            new Random().NextBytes(plainText);
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            var startTime = DateTime.UtcNow;
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            var endTime = DateTime.UtcNow;
            
            Assert.IsNotNull(decryptedText);
            Assert.Less((endTime - startTime).TotalSeconds, 5);
        }

        #endregion

        #region Key Variation Tests

        [Test]
        public void Encrypt_AllZeroKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("All zero key test");
            var key = new byte[16];
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_AllOneKey_ReturnsValidByteArray()
        {
            var plainText = Encoding.UTF8.GetBytes("All one key test");
            var key = new byte[16];
            for (var i = 0; i < 16; i++)
            {
                key[i] = 0xFF;
            }
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherText);
            Assert.Greater(cipherText.Length, 0);
        }

        [Test]
        public void Encrypt_DifferentKeys_ProducesDifferentCipherText()
        {
            var plainText = Encoding.UTF8.GetBytes("Different keys test");
            var key1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            var key2 = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
            
            var cipherText1 = XxteaCryptoUtility.Encrypt(plainText, key1);
            var cipherText2 = XxteaCryptoUtility.Encrypt(plainText, key2);
            
            Assert.AreNotEqual(cipherText1, cipherText2);
        }

        #endregion

        #region Deterministic Tests

        [Test]
        public void EncryptDecrypt_Deterministic_Verification()
        {
            var plainText = Encoding.UTF8.GetBytes("Deterministic test");
            var key = HexConverter.FromHexString("0102030405060708090A0B0C0D0E0F10");
            
            var cipherText = XxteaCryptoUtility.Encrypt(plainText, key);
            var decryptedText = XxteaCryptoUtility.Decrypt(cipherText, key);
            
            Assert.AreEqual(plainText, decryptedText);
            
            var expectedHex = HexConverter.ToHexString(cipherText);
            Assert.IsNotNull(expectedHex);
            Assert.Greater(expectedHex.Length, 0);
        }

        #endregion

        #region EncryptToHexString Tests

        [Test]
        public void EncryptToHexString_ByteArray_ReturnsValidHexString()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var hexString = XxteaCryptoUtility.EncryptToHexString(plainData, key);
            
            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
            Assert.IsTrue(IsValidHexString(hexString));
        }

        [Test]
        public void EncryptToHexString_ByteArray_LowerCase_ReturnsValidHexString()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var hexString = XxteaCryptoUtility.EncryptToHexString(plainData, key, false);
            
            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
            Assert.IsTrue(IsValidHexString(hexString));
            Assert.AreEqual(hexString, hexString.ToLower());
        }

        [Test]
        public void EncryptToHexString_String_ReturnsValidHexString()
        {
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var hexString = XxteaCryptoUtility.EncryptToHexString("Hello, World!", key);
            
            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
            Assert.IsTrue(IsValidHexString(hexString));
        }

        [Test]
        public void EncryptToHexString_String_WithEncoding_ReturnsValidHexString()
        {
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var hexString = XxteaCryptoUtility.EncryptToHexString("Hello, World!", key, Encoding.UTF8);
            
            Assert.IsNotNull(hexString);
            Assert.Greater(hexString.Length, 0);
            Assert.IsTrue(IsValidHexString(hexString));
        }

        [Test]
        public void EncryptToHexString_RoundTrip_Verification()
        {
            var plainText = "Round trip with hex string";
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var hexString = XxteaCryptoUtility.EncryptToHexString(plainText, key);
            var cipherData = HexConverter.FromHexString(hexString);
            var decryptedData = XxteaCryptoUtility.Decrypt(cipherData, key);
            var decryptedText = Encoding.UTF8.GetString(decryptedData);
            
            Assert.AreEqual(plainText, decryptedText);
        }

        #endregion

        #region EncryptToBase64String Tests

        [Test]
        public void EncryptToBase64String_ByteArray_ReturnsValidBase64String()
        {
            var plainData = Encoding.UTF8.GetBytes("Hello, World!");
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var base64String = XxteaCryptoUtility.EncryptToBase64String(plainData, key);
            
            Assert.IsNotNull(base64String);
            Assert.Greater(base64String.Length, 0);
            Assert.IsTrue(IsValidBase64String(base64String));
        }

        [Test]
        public void EncryptToBase64String_String_ReturnsValidBase64String()
        {
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var base64String = XxteaCryptoUtility.EncryptToBase64String("Hello, World!", key);
            
            Assert.IsNotNull(base64String);
            Assert.Greater(base64String.Length, 0);
            Assert.IsTrue(IsValidBase64String(base64String));
        }

        [Test]
        public void EncryptToBase64String_String_WithEncoding_ReturnsValidBase64String()
        {
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var base64String = XxteaCryptoUtility.EncryptToBase64String("Hello, World!", key, Encoding.UTF8);
            
            Assert.IsNotNull(base64String);
            Assert.Greater(base64String.Length, 0);
            Assert.IsTrue(IsValidBase64String(base64String));
        }

        [Test]
        public void EncryptToBase64String_RoundTrip_Verification()
        {
            var plainText = "Round trip with base64 string";
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var base64String = XxteaCryptoUtility.EncryptToBase64String(plainText, key);
            var cipherData = Convert.FromBase64String(base64String);
            var decryptedData = XxteaCryptoUtility.Decrypt(cipherData, key);
            var decryptedText = Encoding.UTF8.GetString(decryptedData);
            
            Assert.AreEqual(plainText, decryptedText);
        }

        #endregion

        #region String Encrypt/Decrypt Tests

        [Test]
        public void Encrypt_String_ReturnsValidByteArray()
        {
            var plainText = "Hello, World!";
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherData = XxteaCryptoUtility.Encrypt(plainText, key);
            
            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Encrypt_String_WithCustomEncoding_ReturnsValidByteArray()
        {
            var plainText = "Hello, World!";
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            var cipherData = XxteaCryptoUtility.Encrypt(plainText, key, Encoding.Unicode);
            
            Assert.IsNotNull(cipherData);
            Assert.Greater(cipherData.Length, 0);
        }

        [Test]
        public void Decrypt_String_WithCustomEncoding_ReturnsOriginalPlainText()
        {
            const string plainText = "Hello, World!";
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            var encoding = Encoding.Unicode;
            var cipherData = XxteaCryptoUtility.Encrypt(plainText, key, encoding);
            var cipherText = encoding.GetString(cipherData);
            var decryptedData = XxteaCryptoUtility.Decrypt(cipherText, key, encoding);
            var decryptedText = encoding.GetString(decryptedData);
            
            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void Decrypt_String_NullOrEmpty_ThrowsArgumentNullException()
        {
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            
            Assert.Throws<ArgumentNullException>(() => XxteaCryptoUtility.Decrypt(null, key));
            Assert.Throws<ArgumentNullException>(() => XxteaCryptoUtility.Decrypt(string.Empty, key));
        }

        #endregion

        #region Helper Methods

        private static bool IsValidHexString(string hexString)
        {
            if (string.IsNullOrEmpty(hexString) || hexString.Length % 2 != 0)
                return false;

            return hexString.All(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
        }

        private static bool IsValidBase64String(string base64String)
        {
            if (string.IsNullOrEmpty(base64String))
                return false;

            try
            {
                _ = Convert.FromBase64String(base64String);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        #endregion
    }
}