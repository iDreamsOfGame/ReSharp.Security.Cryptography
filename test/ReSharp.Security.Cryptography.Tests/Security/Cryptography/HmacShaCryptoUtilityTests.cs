using System;
using System.Text;
using NUnit.Framework;

// ReSharper disable AssignNullToNotNullAttribute

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class HmacShaCryptoUtilityTests
    {
        private const string SampleKeyString = "secret_key";
        
        private static readonly byte[] SampleData = Encoding.UTF8.GetBytes("1234abcd");
        
        private static readonly byte[] SampleKeyBytes = Encoding.UTF8.GetBytes(SampleKeyString);

        private static readonly byte[] EmptyData = Array.Empty<byte>();
        
        private static readonly byte[] EmptyKey = Array.Empty<byte>();

        #region HMAC-SHA1 Tests

        [Test]
        public void ComputeHmacSha1Hash_ByteDataByteKey_ReturnsCorrectHashLength()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha1Hash(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(20, hash.Length); // SHA1 is 160 bits = 20 bytes
        }

        [Test]
        public void ComputeHmacSha1Hash_ByteDataByteKey_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash(null!, SampleKeyBytes));
        }

        [Test]
        public void ComputeHmacSha1Hash_ByteDataByteKey_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash(EmptyData, SampleKeyBytes));
        }

        [Test]
        public void ComputeHmacSha1Hash_ByteDataByteKey_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash(SampleData, null!));
        }

        [Test]
        public void ComputeHmacSha1Hash_ByteDataByteKey_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash(SampleData, EmptyKey));
        }

        [Test]
        public void ComputeHmacSha1HashToHexString_ByteDataByteKey_DefaultUppercase_ReturnsCorrectFormat()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha1HashToHexString(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(40, actual.Length);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeHmacSha1HashToHexString_ByteDataByteKey_ToLowercase_ReturnsLowercase()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha1HashToHexString(SampleData, SampleKeyBytes, toUppercase: false);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(40, actual.Length);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHmacSha1HashToBase64String_ByteDataByteKey_ReturnsCorrectFormat()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha1HashToBase64String(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(28, actual.Length); // Base64 of 20 bytes is usually 28 chars (with padding)
        }

        [Test]
        public void ComputeHmacSha1Hash_StringDataStringKey_ValidInput_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var hash = HmacShaCryptoUtility.ComputeHmacSha1Hash(plainText, SampleKeyString);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(20, hash.Length);
        }

        [Test]
        public void ComputeHmacSha1Hash_StringDataStringKey_NullText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash((string)null!, SampleKeyString));
        }

        [Test]
        public void ComputeHmacSha1Hash_StringDataStringKey_EmptyText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash(string.Empty, SampleKeyString));
        }

        [Test]
        public void ComputeHmacSha1Hash_StringDataStringKey_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash("test", (string)null!));
        }

        [Test]
        public void ComputeHmacSha1Hash_StringDataStringKey_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha1Hash("test", string.Empty));
        }

        [Test]
        public void ComputeHmacSha1Hash_StringDataStringKey_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hashUtf8 = HmacShaCryptoUtility.ComputeHmacSha1Hash(plainText, SampleKeyString, Encoding.UTF8);
            var hashUnicode = HmacShaCryptoUtility.ComputeHmacSha1Hash(plainText, SampleKeyString, Encoding.Unicode);
            
            Assert.IsNotNull(hashUtf8);
            Assert.IsNotNull(hashUnicode);
            Assert.AreEqual(20, hashUtf8.Length);
            Assert.AreNotEqual(hashUtf8, hashUnicode);
        }

        [Test]
        public void ComputeHmacSha1HashToHexString_StringDataStringKey_ValidInput_ReturnsHexString()
        {
            var hex = HmacShaCryptoUtility.ComputeHmacSha1HashToHexString("1234abcd", SampleKeyString);
            Assert.IsNotNull(hex);
            Assert.AreEqual(40, hex.Length);
        }

        [Test]
        public void ComputeHmacSha1HashToBase64String_StringDataStringKey_ValidInput_ReturnsBase64()
        {
            var base64 = HmacShaCryptoUtility.ComputeHmacSha1HashToBase64String("1234abcd", SampleKeyString);
            Assert.IsNotNull(base64);
            Assert.AreEqual(28, base64.Length);
        }

        [Test]
        public void ComputeHmacSha1Hash_Consistency_SameInputProducesSameHash()
        {
            var hash1 = HmacShaCryptoUtility.ComputeHmacSha1Hash(SampleData, SampleKeyBytes);
            var hash2 = HmacShaCryptoUtility.ComputeHmacSha1Hash(SampleData, SampleKeyBytes);
            
            Assert.AreEqual(hash1, hash2);
        }

        #endregion

        #region HMAC-SHA256 Tests

        [Test]
        public void ComputeHmacSha256Hash_ByteDataByteKey_ReturnsCorrectHashLength()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha256Hash(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(32, hash.Length); // SHA256 is 256 bits = 32 bytes
        }

        [Test]
        public void ComputeHmacSha256Hash_ByteDataByteKey_NullOrEmptyArgs_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash(null!, SampleKeyBytes));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash(EmptyData, SampleKeyBytes));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash(SampleData, null!));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash(SampleData, EmptyKey));
        }

        [Test]
        public void ComputeHmacSha256HashToHexString_ByteDataByteKey_DefaultUppercase_ReturnsCorrectFormat()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha256HashToHexString(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(64, actual.Length);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeHmacSha256HashToHexString_ByteDataByteKey_ToLowercase_ReturnsLowercase()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha256HashToHexString(SampleData, SampleKeyBytes, toUppercase: false);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(64, actual.Length);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHmacSha256HashToBase64String_ByteDataByteKey_ReturnsCorrectFormat()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha256HashToBase64String(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(44, actual.Length); // Base64 of 32 bytes
        }

        [Test]
        public void ComputeHmacSha256Hash_StringDataStringKey_ValidInput_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var hash = HmacShaCryptoUtility.ComputeHmacSha256Hash(plainText, SampleKeyString);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(32, hash.Length);
        }

        [Test]
        public void ComputeHmacSha256Hash_StringDataStringKey_NullOrEmptyArgs_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash((string)null!, SampleKeyString));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash(string.Empty, SampleKeyString));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash("test", (string)null!));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha256Hash("test", string.Empty));
        }

        [Test]
        public void ComputeHmacSha256Hash_StringDataStringKey_WithEncoding_ReturnsDifferentHashesForDifferentEncodings()
        {
            const string plainText = "你好";
            var hashUtf8 = HmacShaCryptoUtility.ComputeHmacSha256Hash(plainText, SampleKeyString, Encoding.UTF8);
            var hashUnicode = HmacShaCryptoUtility.ComputeHmacSha256Hash(plainText, SampleKeyString, Encoding.Unicode);
            
            Assert.AreNotEqual(hashUtf8, hashUnicode);
        }

        [Test]
        public void ComputeHmacSha256HashToHexString_StringDataStringKey_ValidInput_ReturnsHexString()
        {
            var hex = HmacShaCryptoUtility.ComputeHmacSha256HashToHexString("1234abcd", SampleKeyString);
            Assert.IsNotNull(hex);
            Assert.AreEqual(64, hex.Length);
        }

        [Test]
        public void ComputeHmacSha256HashToBase64String_StringDataStringKey_ValidInput_ReturnsBase64()
        {
            var base64 = HmacShaCryptoUtility.ComputeHmacSha256HashToBase64String("1234abcd", SampleKeyString);
            Assert.IsNotNull(base64);
            Assert.AreEqual(44, base64.Length);
        }

        #endregion

        #region HMAC-SHA384 Tests

        [Test]
        public void ComputeHmacSha384Hash_ByteDataByteKey_ReturnsCorrectHashLength()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha384Hash(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(48, hash.Length); // SHA384 is 384 bits = 48 bytes
        }

        [Test]
        public void ComputeHmacSha384Hash_ByteDataByteKey_NullOrEmptyArgs_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash(null!, SampleKeyBytes));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash(EmptyData, SampleKeyBytes));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash(SampleData, null!));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash(SampleData, EmptyKey));
        }

        [Test]
        public void ComputeHmacSha384HashToHexString_ByteDataByteKey_ReturnsCorrectFormat()
        {
            var actualUpper = HmacShaCryptoUtility.ComputeHmacSha384HashToHexString(SampleData, SampleKeyBytes, toUppercase: true);
            var actualLower = HmacShaCryptoUtility.ComputeHmacSha384HashToHexString(SampleData, SampleKeyBytes, toUppercase: false);
            
            Assert.AreEqual(96, actualUpper.Length);
            Assert.AreEqual(96, actualLower.Length);
            Assert.IsTrue(actualUpper == actualUpper.ToUpper());
            Assert.IsTrue(actualLower == actualLower.ToLower());
        }

        [Test]
        public void ComputeHmacSha384HashToBase64String_ByteDataByteKey_ReturnsCorrectFormat()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha384HashToBase64String(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(64, actual.Length); // Base64 of 48 bytes
        }

        [Test]
        public void ComputeHmacSha384Hash_StringDataStringKey_ValidInput_ReturnsCorrectHash()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha384Hash("1234abcd", SampleKeyString);
            Assert.IsNotNull(hash);
            Assert.AreEqual(48, hash.Length);
        }

        [Test]
        public void ComputeHmacSha384Hash_StringDataStringKey_NullOrEmptyArgs_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash((string)null!, SampleKeyString));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash(string.Empty, SampleKeyString));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash("test", (string)null!));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha384Hash("test", string.Empty));
        }

        [Test]
        public void ComputeHmacSha384HashToHexString_StringDataStringKey_ReturnsHexString()
        {
            var hex = HmacShaCryptoUtility.ComputeHmacSha384HashToHexString("1234abcd", SampleKeyString);
            Assert.IsNotNull(hex);
            Assert.AreEqual(96, hex.Length);
        }

        [Test]
        public void ComputeHmacSha384HashToBase64String_StringDataStringKey_ReturnsBase64()
        {
            var base64 = HmacShaCryptoUtility.ComputeHmacSha384HashToBase64String("1234abcd", SampleKeyString);
            Assert.IsNotNull(base64);
            Assert.AreEqual(64, base64.Length);
        }

        #endregion

        #region HMAC-SHA512 Tests

        [Test]
        public void ComputeHmacSha512Hash_ByteDataByteKey_ReturnsCorrectHashLength()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha512Hash(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(64, hash.Length); // SHA512 is 512 bits = 64 bytes
        }

        [Test]
        public void ComputeHmacSha512Hash_ByteDataByteKey_NullOrEmptyArgs_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash(null!, SampleKeyBytes));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash(EmptyData, SampleKeyBytes));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash(SampleData, null!));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash(SampleData, EmptyKey));
        }

        [Test]
        public void ComputeHmacSha512HashToHexString_ByteDataByteKey_ReturnsCorrectFormat()
        {
            var actualUpper = HmacShaCryptoUtility.ComputeHmacSha512HashToHexString(SampleData, SampleKeyBytes, toUppercase: true);
            var actualLower = HmacShaCryptoUtility.ComputeHmacSha512HashToHexString(SampleData, SampleKeyBytes, toUppercase: false);
            
            Assert.AreEqual(128, actualUpper.Length);
            Assert.AreEqual(128, actualLower.Length);
            Assert.IsTrue(actualUpper == actualUpper.ToUpper());
            Assert.IsTrue(actualLower == actualLower.ToLower());
        }

        [Test]
        public void ComputeHmacSha512HashToBase64String_ByteDataByteKey_ReturnsCorrectFormat()
        {
            var actual = HmacShaCryptoUtility.ComputeHmacSha512HashToBase64String(SampleData, SampleKeyBytes);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(88, actual.Length); // Base64 of 64 bytes
        }

        [Test]
        public void ComputeHmacSha512Hash_StringDataStringKey_ValidInput_ReturnsCorrectHash()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha512Hash("1234abcd", SampleKeyString);
            Assert.IsNotNull(hash);
            Assert.AreEqual(64, hash.Length);
        }

        [Test]
        public void ComputeHmacSha512Hash_StringDataStringKey_NullOrEmptyArgs_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash((string)null!, SampleKeyString));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash(string.Empty, SampleKeyString));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash("test", (string)null!));
            Assert.Throws<ArgumentNullException>(() => HmacShaCryptoUtility.ComputeHmacSha512Hash("test", string.Empty));
        }

        [Test]
        public void ComputeHmacSha512HashToHexString_StringDataStringKey_ReturnsHexString()
        {
            var hex = HmacShaCryptoUtility.ComputeHmacSha512HashToHexString("1234abcd", SampleKeyString);
            Assert.IsNotNull(hex);
            Assert.AreEqual(128, hex.Length);
        }

        [Test]
        public void ComputeHmacSha512HashToBase64String_StringDataStringKey_ReturnsBase64()
        {
            var base64 = HmacShaCryptoUtility.ComputeHmacSha512HashToBase64String("1234abcd", SampleKeyString);
            Assert.IsNotNull(base64);
            Assert.AreEqual(88, base64.Length);
        }

        #endregion

        #region Mixed Input Type Tests (Byte Data + String Key / String Data + Byte Key)

        [Test]
        public void ComputeHmacSha256Hash_ByteDataStringKey_ReturnsValidHash()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha256Hash(SampleData, SampleKeyString);
            Assert.IsNotNull(hash);
            Assert.AreEqual(32, hash.Length);
        }

        [Test]
        public void ComputeHmacSha256Hash_StringDataByteKey_ReturnsValidHash()
        {
            var hash = HmacShaCryptoUtility.ComputeHmacSha256Hash("1234abcd", SampleKeyBytes);
            Assert.IsNotNull(hash);
            Assert.AreEqual(32, hash.Length);
        }

        [Test]
        public void ComputeHmacSha256HashToHexString_ByteDataStringKey_ReturnsValidHex()
        {
            var hex = HmacShaCryptoUtility.ComputeHmacSha256HashToHexString(SampleData, SampleKeyString);
            Assert.IsNotNull(hex);
            Assert.AreEqual(64, hex.Length);
        }

        [Test]
        public void ComputeHmacSha256HashToBase64String_StringDataByteKey_ReturnsValidBase64()
        {
            var base64 = HmacShaCryptoUtility.ComputeHmacSha256HashToBase64String("1234abcd", SampleKeyBytes);
            Assert.IsNotNull(base64);
            Assert.AreEqual(44, base64.Length);
        }

        #endregion

        #region Cross-Algorithm & Consistency Tests

        [Test]
        public void DifferentHmacAlgorithms_ProduceDifferentHashes_ForSameInput()
        {
            var hmacSha1 = HmacShaCryptoUtility.ComputeHmacSha1Hash(SampleData, SampleKeyBytes);
            var hmacSha256 = HmacShaCryptoUtility.ComputeHmacSha256Hash(SampleData, SampleKeyBytes);
            var hmacSha384 = HmacShaCryptoUtility.ComputeHmacSha384Hash(SampleData, SampleKeyBytes);
            var hmacSha512 = HmacShaCryptoUtility.ComputeHmacSha512Hash(SampleData, SampleKeyBytes);
            
            Assert.AreNotEqual(hmacSha1, hmacSha256);
            Assert.AreNotEqual(hmacSha1, hmacSha384);
            Assert.AreNotEqual(hmacSha1, hmacSha512);
            Assert.AreNotEqual(hmacSha256, hmacSha384);
            Assert.AreNotEqual(hmacSha256, hmacSha512);
            Assert.AreNotEqual(hmacSha384, hmacSha512);
        }

        [Test]
        public void HmacHashLengths_AreCorrect_ForAllAlgorithms()
        {
            var hmacSha1 = HmacShaCryptoUtility.ComputeHmacSha1Hash(SampleData, SampleKeyBytes);
            var hmacSha256 = HmacShaCryptoUtility.ComputeHmacSha256Hash(SampleData, SampleKeyBytes);
            var hmacSha384 = HmacShaCryptoUtility.ComputeHmacSha384Hash(SampleData, SampleKeyBytes);
            var hmacSha512 = HmacShaCryptoUtility.ComputeHmacSha512Hash(SampleData, SampleKeyBytes);
            
            Assert.AreEqual(20, hmacSha1.Length);
            Assert.AreEqual(32, hmacSha256.Length);
            Assert.AreEqual(48, hmacSha384.Length);
            Assert.AreEqual(64, hmacSha512.Length);
        }

        [Test]
        public void StringParameters_ProduceSameHash_AsByteArrayParameters()
        {
            const string plainText = "1234abcd";
            const string key = "secret_key";
            
            // SHA1
            var sha1String = HmacShaCryptoUtility.ComputeHmacSha1Hash(plainText, key);
            var sha1Bytes = HmacShaCryptoUtility.ComputeHmacSha1Hash(Encoding.UTF8.GetBytes(plainText), Encoding.UTF8.GetBytes(key));
            Assert.AreEqual(sha1String, sha1Bytes);
            
            // SHA256
            var sha256String = HmacShaCryptoUtility.ComputeHmacSha256Hash(plainText, key);
            var sha256Bytes = HmacShaCryptoUtility.ComputeHmacSha256Hash(Encoding.UTF8.GetBytes(plainText), Encoding.UTF8.GetBytes(key));
            Assert.AreEqual(sha256String, sha256Bytes);
            
            // SHA384
            var sha384String = HmacShaCryptoUtility.ComputeHmacSha384Hash(plainText, key);
            var sha384Bytes = HmacShaCryptoUtility.ComputeHmacSha384Hash(Encoding.UTF8.GetBytes(plainText), Encoding.UTF8.GetBytes(key));
            Assert.AreEqual(sha384String, sha384Bytes);
            
            // SHA512
            var sha512String = HmacShaCryptoUtility.ComputeHmacSha512Hash(plainText, key);
            var sha512Bytes = HmacShaCryptoUtility.ComputeHmacSha512Hash(Encoding.UTF8.GetBytes(plainText), Encoding.UTF8.GetBytes(key));
            Assert.AreEqual(sha512String, sha512Bytes);
        }

        [Test]
        public void DefaultEncoding_IsUtf8_ForAllAlgorithms()
        {
            const string plainText = "你好";
            const string key = "key";
            
            var sha1Default = HmacShaCryptoUtility.ComputeHmacSha1Hash(plainText, key);
            var sha1Utf8 = HmacShaCryptoUtility.ComputeHmacSha1Hash(plainText, key, Encoding.UTF8);
            Assert.AreEqual(sha1Default, sha1Utf8);
            
            var sha256Default = HmacShaCryptoUtility.ComputeHmacSha256Hash(plainText, key);
            var sha256Utf8 = HmacShaCryptoUtility.ComputeHmacSha256Hash(plainText, key, Encoding.UTF8);
            Assert.AreEqual(sha256Default, sha256Utf8);
            
            var sha384Default = HmacShaCryptoUtility.ComputeHmacSha384Hash(plainText, key);
            var sha384Utf8 = HmacShaCryptoUtility.ComputeHmacSha384Hash(plainText, key, Encoding.UTF8);
            Assert.AreEqual(sha384Default, sha384Utf8);
            
            var sha512Default = HmacShaCryptoUtility.ComputeHmacSha512Hash(plainText, key);
            var sha512Utf8 = HmacShaCryptoUtility.ComputeHmacSha512Hash(plainText, key, Encoding.UTF8);
            Assert.AreEqual(sha512Default, sha512Utf8);
        }

        [Test]
        public void LargeData_ReturnsValidHashes()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hash1 = HmacShaCryptoUtility.ComputeHmacSha1Hash(largeData, SampleKeyBytes);
            var hash256 = HmacShaCryptoUtility.ComputeHmacSha256Hash(largeData, SampleKeyBytes);
            var hash384 = HmacShaCryptoUtility.ComputeHmacSha384Hash(largeData, SampleKeyBytes);
            var hash512 = HmacShaCryptoUtility.ComputeHmacSha512Hash(largeData, SampleKeyBytes);
            
            Assert.AreEqual(20, hash1.Length);
            Assert.AreEqual(32, hash256.Length);
            Assert.AreEqual(48, hash384.Length);
            Assert.AreEqual(64, hash512.Length);
        }

        #endregion
    }
}