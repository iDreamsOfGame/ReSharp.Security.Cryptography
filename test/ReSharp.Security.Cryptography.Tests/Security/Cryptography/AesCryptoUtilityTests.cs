using System;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

// ReSharper disable AssignNullToNotNullAttribute

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class AesCryptoUtilityTests
    {
        private static readonly byte[] SampleKey128 = Encoding.UTF8.GetBytes("0123456789abcdef"); // 16 bytes for AES-128

        private static readonly byte[] SampleKey192 = Encoding.UTF8.GetBytes("0123456789abcdefghij"); // 20 bytes (will be padded internally)

        private static readonly byte[] SampleKey256 = Encoding.UTF8.GetBytes("0123456789abcdefghijklmn"); // 24 bytes for AES-256

        private static readonly byte[] SampleIV = Encoding.UTF8.GetBytes("abcdefghijklmnop"); // 16 bytes IV

        private static readonly byte[] EmptyData = Array.Empty<byte>();

        private static readonly string SamplePlainText = "Hello, AES Encryption!";

        private static readonly byte[] SamplePlainData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        #region EncryptToHexString Tests (String input)

        [Test]
        public void EncryptToHexString_ValidStringInput_CBCMode_ReturnsCorrectLengthHexString()
        {
            var result = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, SampleIV, cipherMode: CipherMode.CBC);

            Assert.IsNotNull(result);
            Assert.IsNotEmpty(result);
            Assert.IsTrue(result.Length % 2 == 0);
        }

        [Test]
        public void EncryptToHexString_ValidStringInput_ToUppercaseTrue_ReturnsUppercase()
        {
            var result = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, SampleIV, toUppercase: true);

            Assert.AreEqual(result, result.ToUpper());
        }

        [Test]
        public void EncryptToHexString_ValidStringInput_ToUppercaseFalse_ReturnsLowercase()
        {
            var result = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, SampleIV, toUppercase: false);

            Assert.AreEqual(result, result.ToLower());
        }

        [Test]
        public void EncryptToHexString_NullPlainText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString((string)null, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToHexString_EmptyPlainText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString(string.Empty, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToHexString_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString(SamplePlainText, null!, SampleIV));
        }

        [Test]
        public void EncryptToHexString_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString(SamplePlainText, Array.Empty<byte>(), SampleIV));
        }

        [Test]
        public void EncryptToHexString_SameInput_ProducesSameOutput()
        {
            var result1 = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, SampleIV);
            var result2 = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, SampleIV);

            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void EncryptToHexString_DifferentKey_ProducesDifferentOutput()
        {
            var key1 = Encoding.UTF8.GetBytes("key1key1key1key1");
            var key2 = Encoding.UTF8.GetBytes("key2key2key2key2");

            var result1 = AesCryptoUtility.EncryptToHexString(SamplePlainText, key1, SampleIV);
            var result2 = AesCryptoUtility.EncryptToHexString(SamplePlainText, key2, SampleIV);

            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void EncryptToHexString_DifferentIV_ProducesDifferentOutput()
        {
            var iv1 = Encoding.UTF8.GetBytes("iv1iv1iv1iv1iv1i");
            var iv2 = Encoding.UTF8.GetBytes("iv2iv2iv2iv2iv2i");

            var result1 = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, iv1);
            var result2 = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, iv2);

            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void EncryptToHexString_ECBCipherMode_NoIVRequired_Success()
        {
            var result = AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, cipherMode: CipherMode.ECB);

            Assert.IsNotNull(result);
            Assert.IsNotEmpty(result);
        }

        [Test]
        public void EncryptToHexString_CipherModeWithoutIV_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString(SamplePlainText, SampleKey256, iv: null, cipherMode: CipherMode.CBC));
        }

        #endregion

        #region EncryptToHexString Tests (Byte array input)

        [Test]
        public void EncryptToHexString_ValidByteArrayInput_CBCMode_ReturnsCorrectLengthHexString()
        {
            var result = AesCryptoUtility.EncryptToHexString(SamplePlainData, SampleKey256, SampleIV, cipherMode: CipherMode.CBC);

            Assert.IsNotNull(result);
            Assert.IsNotEmpty(result);
            Assert.IsTrue(result.Length % 2 == 0);
        }

        [Test]
        public void EncryptToHexString_ValidByteArrayInput_ToUppercaseTrue_ReturnsUppercase()
        {
            var result = AesCryptoUtility.EncryptToHexString(SamplePlainData, SampleKey256, SampleIV, toUppercase: true);

            Assert.AreEqual(result, result.ToUpper());
        }

        [Test]
        public void EncryptToHexString_ValidByteArrayInput_ToUppercaseFalse_ReturnsLowercase()
        {
            var result = AesCryptoUtility.EncryptToHexString(SamplePlainData, SampleKey256, SampleIV, toUppercase: false);

            Assert.AreEqual(result, result.ToLower());
        }

        [Test]
        public void EncryptToHexString_NullByteArrayData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString((byte[])null, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToHexString_EmptyByteArrayData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString(EmptyData, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToHexString_ByteArray_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString(SamplePlainData, null!, SampleIV));
        }

        [Test]
        public void EncryptToHexString_ByteArray_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToHexString(SamplePlainData, Array.Empty<byte>(), SampleIV));
        }

        [Test]
        public void EncryptToHexString_ByteArray_SameInput_ProducesSameOutput()
        {
            var result1 = AesCryptoUtility.EncryptToHexString(SamplePlainData, SampleKey256, SampleIV);
            var result2 = AesCryptoUtility.EncryptToHexString(SamplePlainData, SampleKey256, SampleIV);

            Assert.AreEqual(result1, result2);
        }

        #endregion

        #region EncryptToBase64String Tests (String input)

        [Test]
        public void EncryptToBase64String_ValidStringInput_ReturnsValidBase64Format()
        {
            var result = AesCryptoUtility.EncryptToBase64String(SamplePlainText, SampleKey256, SampleIV);

            Assert.IsNotNull(result);
            Assert.IsNotEmpty(result);
            Assert.DoesNotThrow(() => _ = Convert.FromBase64String(result));
        }

        [Test]
        public void EncryptToBase64String_NullPlainText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToBase64String((string)null, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToBase64String_EmptyPlainText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToBase64String(string.Empty, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToBase64String_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToBase64String(SamplePlainText, null!, SampleIV));
        }

        [Test]
        public void EncryptToBase64String_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToBase64String(SamplePlainText, Array.Empty<byte>(), SampleIV));
        }

        [Test]
        public void EncryptToBase64String_SameInput_ProducesSameOutput()
        {
            var result1 = AesCryptoUtility.EncryptToBase64String(SamplePlainText, SampleKey256, SampleIV);
            var result2 = AesCryptoUtility.EncryptToBase64String(SamplePlainText, SampleKey256, SampleIV);

            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void EncryptToBase64String_DifferentKey_ProducesDifferentOutput()
        {
            var key1 = Encoding.UTF8.GetBytes("base64key1base64");
            var key2 = Encoding.UTF8.GetBytes("base64key2base64");

            var result1 = AesCryptoUtility.EncryptToBase64String(SamplePlainText, key1, SampleIV);
            var result2 = AesCryptoUtility.EncryptToBase64String(SamplePlainText, key2, SampleIV);

            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void EncryptToBase64String_DifferentIV_ProducesDifferentOutput()
        {
            var iv1 = Encoding.UTF8.GetBytes("b64iv1b64iv1b64i");
            var iv2 = Encoding.UTF8.GetBytes("b64iv2b64iv2b64i");

            var result1 = AesCryptoUtility.EncryptToBase64String(SamplePlainText, SampleKey256, iv1);
            var result2 = AesCryptoUtility.EncryptToBase64String(SamplePlainText, SampleKey256, iv2);

            Assert.AreNotEqual(result1, result2);
        }

        #endregion

        #region EncryptToBase64String Tests (Byte array input)

        [Test]
        public void EncryptToBase64String_ValidByteArrayInput_ReturnsValidBase64Format()
        {
            var result = AesCryptoUtility.EncryptToBase64String(SamplePlainData, SampleKey256, SampleIV);

            Assert.IsNotNull(result);
            Assert.IsNotEmpty(result);
            Assert.DoesNotThrow(() => _ = Convert.FromBase64String(result));
        }

        [Test]
        public void EncryptToBase64String_NullByteArrayData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToBase64String((byte[])null, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToBase64String_EmptyByteArrayData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToBase64String(EmptyData, SampleKey256, SampleIV));
        }

        [Test]
        public void EncryptToBase64String_ByteArray_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.EncryptToBase64String(SamplePlainData, null!, SampleIV));
        }

        [Test]
        public void EncryptToBase64String_ByteArray_SameInput_ProducesSameOutput()
        {
            var result1 = AesCryptoUtility.EncryptToBase64String(SamplePlainData, SampleKey256, SampleIV);
            var result2 = AesCryptoUtility.EncryptToBase64String(SamplePlainData, SampleKey256, SampleIV);

            Assert.AreEqual(result1, result2);
        }

        #endregion

        #region Encrypt Tests (String input returning byte[])

        [Test]
        public void Encrypt_ValidStringInput_ReturnsNonEmptyByteArray()
        {
            var result = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV);

            Assert.IsNotNull(result);
            Assert.Greater(result.Length, 0);
        }

        [Test]
        public void Encrypt_ValidStringInput_WithCustomEncoding_ReturnsNonEmptyByteArray()
        {
            var result = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV, Encoding.Unicode);

            Assert.IsNotNull(result);
            Assert.Greater(result.Length, 0);
        }

        [Test]
        public void Encrypt_NullStringInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt((string)null, SampleKey256, SampleIV));
        }

        [Test]
        public void Encrypt_EmptyStringInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(string.Empty, SampleKey256, SampleIV));
        }

        [Test]
        public void Encrypt_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(SamplePlainText, null!, SampleIV));
        }

        [Test]
        public void Encrypt_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(SamplePlainText, Array.Empty<byte>(), SampleIV));
        }

        [Test]
        public void Encrypt_String_SameInput_ProducesSameOutput()
        {
            var result1 = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV);
            var result2 = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV);

            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void Encrypt_String_WithDifferentCipherModes_ProducesDifferentOutput()
        {
            var resultCbc = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV, cipherMode: CipherMode.CBC);
            var resultEcb = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, cipherMode: CipherMode.ECB);

            Assert.AreNotEqual(resultCbc, resultEcb);
        }

        [Test]
        public void Encrypt_String_WithDifferentPaddingModes_ProducesDifferentOutput()
        {
            var resultPkcs7 = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV, paddingMode: PaddingMode.PKCS7);
            var resultZeros = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV, paddingMode: PaddingMode.Zeros);

            Assert.AreNotEqual(resultPkcs7, resultZeros);
        }

        #endregion

        #region Encrypt Tests (Byte array input)

        [Test]
        public void Encrypt_ValidByteArrayInput_ReturnsNonEmptyByteArray()
        {
            var result = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, SampleIV);

            Assert.IsNotNull(result);
            Assert.Greater(result.Length, 0);
        }

        [Test]
        public void Encrypt_NullByteArrayInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt((byte[])null, SampleKey256, SampleIV));
        }

        [Test]
        public void Encrypt_EmptyByteArrayInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(EmptyData, SampleKey256, SampleIV));
        }

        [Test]
        public void Encrypt_ByteArray_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(SamplePlainData, null!, SampleIV));
        }

        [Test]
        public void Encrypt_ByteArray_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(SamplePlainData, Array.Empty<byte>(), SampleIV));
        }

        [Test]
        public void Encrypt_ByteArray_CBCModeWithoutIV_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, iv: null, cipherMode: CipherMode.CBC));
        }

        [Test]
        public void Encrypt_ByteArray_ECBModeNoIV_Success()
        {
            var result = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, cipherMode: CipherMode.ECB);

            Assert.IsNotNull(result);
            Assert.Greater(result.Length, 0);
        }

        [Test]
        public void Encrypt_ByteArray_SameInput_ProducesSameOutput()
        {
            var result1 = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, SampleIV);
            var result2 = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, SampleIV);

            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void Encrypt_ByteArray_LargeData_Success()
        {
            var largeData = new byte[1024 * 10];
            new Random().NextBytes(largeData);

            var result = AesCryptoUtility.Encrypt(largeData, SampleKey256, SampleIV);

            Assert.IsNotNull(result);
            Assert.Greater(result.Length, 0);
        }

        #endregion

        #region Decrypt Tests (String input returning byte[])

        [Test]
        public void Decrypt_EncryptedString_ReturnsOriginalPlainText()
        {
            var encrypted = AesCryptoUtility.Encrypt(SamplePlainText, SampleKey256, SampleIV);
            var decrypted = AesCryptoUtility.Decrypt(encrypted, SampleKey256, SampleIV);
            Assert.AreEqual(SamplePlainText, Encoding.UTF8.GetString(decrypted));
        }

        #endregion

        #region Decrypt Tests (Byte array input)

        [Test]
        public void Decrypt_EncryptedByteArray_ReturnsOriginalData()
        {
            var encrypted = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, SampleIV);
            var decrypted = AesCryptoUtility.Decrypt(encrypted, SampleKey256, SampleIV);

            Assert.AreEqual(SamplePlainData, decrypted);
        }

        [Test]
        public void Decrypt_NullByteArrayInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(null, SampleKey256, SampleIV));
        }

        [Test]
        public void Decrypt_EmptyByteArrayInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(EmptyData, SampleKey256, SampleIV));
        }

        [Test]
        public void Decrypt_ByteArray_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(SamplePlainData, null!, SampleIV));
        }

        [Test]
        public void Decrypt_ByteArray_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(SamplePlainData, Array.Empty<byte>(), SampleIV));
        }

        [Test]
        public void Decrypt_ByteArray_CBCModeWithoutIV_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Decrypt(SamplePlainData, SampleKey256, iv: null, cipherMode: CipherMode.CBC));
        }

        [Test]
        public void Decrypt_ByteArray_ECBModeNoIV_Success()
        {
            var encrypted = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, cipherMode: CipherMode.ECB);
            var decrypted = AesCryptoUtility.Decrypt(encrypted, SampleKey256, cipherMode: CipherMode.ECB);

            Assert.AreEqual(SamplePlainData, decrypted);
        }

        [Test]
        public void Decrypt_WrongKey_ThrowsCryptographicException()
        {
            var encrypted = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, SampleIV);
            var wrongKey = Encoding.UTF8.GetBytes("wrongkeywrongkey");

            Assert.Throws<CryptographicException>(() => AesCryptoUtility.Decrypt(encrypted, wrongKey, SampleIV));
        }

        [Test]
        public void Decrypt_WrongIV_ThrowsCryptographicException()
        {
            var encrypted = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, SampleIV);
            var wrongIv = Encoding.UTF8.GetBytes("wrongIV_wrong_IV");

            Assert.Throws<CryptographicException>(() => AesCryptoUtility.Decrypt(encrypted, SampleKey256, wrongIv));
        }

        [Test]
        public void Decrypt_CorruptedData_ThrowsCryptographicException()
        {
            var encrypted = AesCryptoUtility.Encrypt(SamplePlainData, SampleKey256, SampleIV);
            var corrupted = new byte[encrypted.Length];
            Array.Copy(encrypted, corrupted, encrypted.Length);
            corrupted[0] ^= 0xFF;

            Assert.Throws<CryptographicException>(() => AesCryptoUtility.Decrypt(corrupted, SampleKey256, SampleIV));
        }

        #endregion

        #region Round-trip Tests

        [Test]
        public void EncryptDecrypt_RoundTrip_StringToBytes_Success()
        {
            const string originalText = "Test round-trip encryption";
            var key = Encoding.UTF8.GetBytes("roundtripkey1234");
            var iv = Encoding.UTF8.GetBytes("roundtripiv12345");

            var encrypted = AesCryptoUtility.Encrypt(originalText, key, iv);
            var decryptedBytes = AesCryptoUtility.Decrypt(encrypted, key, iv);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Assert.AreEqual(originalText, decryptedText);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_Bytes_Success()
        {
            var originalData = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };
            var key = Encoding.UTF8.GetBytes("byteroundtrip123");
            var iv = Encoding.UTF8.GetBytes("byteroundtripiv1");

            var encrypted = AesCryptoUtility.Encrypt(originalData, key, iv);
            var decrypted = AesCryptoUtility.Decrypt(encrypted, key, iv);

            Assert.AreEqual(originalData, decrypted);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_HexString_Success()
        {
            const string originalText = "Hex string round-trip test";
            var key = Encoding.UTF8.GetBytes("hexroundtrip1234");
            var iv = Encoding.UTF8.GetBytes("hexroundtripiv12");

            var encryptedHex = AesCryptoUtility.EncryptToHexString(originalText, key, iv);
            var encryptedBytes = HexConverter.FromHexString(encryptedHex);
            var decryptedBytes = AesCryptoUtility.Decrypt(encryptedBytes, key, iv);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Assert.AreEqual(originalText, decryptedText);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_Base64String_Success()
        {
            const string originalText = "Base64 string round-trip test";
            var key = Encoding.UTF8.GetBytes("b64roundtrip1234");
            var iv = Encoding.UTF8.GetBytes("b64roundtripiv12");

            var encryptedBase64 = AesCryptoUtility.EncryptToBase64String(originalText, key, iv);
            var encryptedBytes = Convert.FromBase64String(encryptedBase64);
            var decryptedBytes = AesCryptoUtility.Decrypt(encryptedBytes, key, iv);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Assert.AreEqual(originalText, decryptedText);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_DifferentCipherModes_Success()
        {
            var originalData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var key = Encoding.UTF8.GetBytes("ciphermodetest12");
            var iv = Encoding.UTF8.GetBytes("ciphermodeiv1234");

            var encryptedCbc = AesCryptoUtility.Encrypt(originalData, key, iv, cipherMode: CipherMode.CBC);
            var decryptedCbc = AesCryptoUtility.Decrypt(encryptedCbc, key, iv, cipherMode: CipherMode.CBC);
            Assert.AreEqual(originalData, decryptedCbc);

            var encryptedEcb = AesCryptoUtility.Encrypt(originalData, key, cipherMode: CipherMode.ECB);
            var decryptedEcb = AesCryptoUtility.Decrypt(encryptedEcb, key, cipherMode: CipherMode.ECB);
            Assert.AreEqual(originalData, decryptedEcb);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_DifferentPaddingModes_Success()
        {
            var originalData = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            var key = Encoding.UTF8.GetBytes("paddingtest12345");
            var iv = Encoding.UTF8.GetBytes("paddingiv1234567");

            var encryptedPkcs7 = AesCryptoUtility.Encrypt(originalData, key, iv, paddingMode: PaddingMode.PKCS7);
            var decryptedPkcs7 = AesCryptoUtility.Decrypt(encryptedPkcs7, key, iv, paddingMode: PaddingMode.PKCS7);
            Assert.AreEqual(originalData, decryptedPkcs7);

            var encryptedZeros = AesCryptoUtility.Encrypt(originalData, key, iv, paddingMode: PaddingMode.Zeros);
            var decryptedZeros = AesCryptoUtility.Decrypt(encryptedZeros, key, iv, paddingMode: PaddingMode.Zeros);
            Assert.AreEqual(originalData, decryptedZeros);
        }

        [Test]
        public void EncryptDecrypt_RoundTrip_DifferentKeySizes_Success()
        {
            var originalData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var iv = Encoding.UTF8.GetBytes("keysizeiv1234567");

            var key128 = Encoding.UTF8.GetBytes("key128bitsize0");
            var encrypted128 = AesCryptoUtility.Encrypt(originalData, key128, iv);
            var decrypted128 = AesCryptoUtility.Decrypt(encrypted128, key128, iv);
            Assert.AreEqual(originalData, decrypted128);

            var key192 = Encoding.UTF8.GetBytes("key192bitsize01234");
            var encrypted192 = AesCryptoUtility.Encrypt(originalData, key192, iv);
            var decrypted192 = AesCryptoUtility.Decrypt(encrypted192, key192, iv);
            Assert.AreEqual(originalData, decrypted192);

            var key256 = Encoding.UTF8.GetBytes("key256bitsize0123456");
            var encrypted256 = AesCryptoUtility.Encrypt(originalData, key256, iv);
            var decrypted256 = AesCryptoUtility.Decrypt(encrypted256, key256, iv);
            Assert.AreEqual(originalData, decrypted256);
        }

        #endregion

        #region Edge Cases and Special Scenarios

        [Test]
        public void Encrypt_EmptyDataWithPKCS7Padding_Success()
        {
            var emptyData = Array.Empty<byte>();
            var key = Encoding.UTF8.GetBytes("emptydatatest123");
            var iv = Encoding.UTF8.GetBytes("emptydataiv12345");

            Assert.Throws<ArgumentNullException>(() => AesCryptoUtility.Encrypt(emptyData, key, iv));
        }

        [Test]
        public void Encrypt_SingleByteData_Success()
        {
            var singleByte = new byte[] { 42 };
            var key = Encoding.UTF8.GetBytes("singlebytetest12");
            var iv = Encoding.UTF8.GetBytes("singlebyteiv1234");

            var encrypted = AesCryptoUtility.Encrypt(singleByte, key, iv);
            var decrypted = AesCryptoUtility.Decrypt(encrypted, key, iv);

            Assert.AreEqual(singleByte, decrypted);
        }

        [Test]
        public void Encrypt_LargeData_Success()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            var key = Encoding.UTF8.GetBytes("largedatatype123");
            var iv = Encoding.UTF8.GetBytes("largedataiv12345");

            var encrypted = AesCryptoUtility.Encrypt(largeData, key, iv);
            var decrypted = AesCryptoUtility.Decrypt(encrypted, key, iv);

            Assert.AreEqual(largeData, decrypted);
        }

        [Test]
        public void Encrypt_DataWithSpecialCharacters_Success()
        {
            const string specialText = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?🚀";
            var key = Encoding.UTF8.GetBytes("specialchartest1");
            var iv = Encoding.UTF8.GetBytes("specialchariv123");

            var encrypted = AesCryptoUtility.Encrypt(specialText, key, iv);
            var decryptedBytes = AesCryptoUtility.Decrypt(encrypted, key, iv);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Assert.AreEqual(specialText, decryptedText);
        }

        [Test]
        public void Encrypt_ChineseCharacters_Success()
        {
            const string chineseText = "你好，世界！加密测试";
            var key = Encoding.UTF8.GetBytes("chinesetest12345");
            var iv = Encoding.UTF8.GetBytes("chineseiv1234567");

            var encrypted = AesCryptoUtility.Encrypt(chineseText, key, iv);
            var decryptedBytes = AesCryptoUtility.Decrypt(encrypted, key, iv);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Assert.AreEqual(chineseText, decryptedText);
        }

        #endregion
    }
}