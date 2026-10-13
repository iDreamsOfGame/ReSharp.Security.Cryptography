using System;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class HmacMd5CryptoUtilityTests
    {
        private static readonly byte[] SampleData = Encoding.UTF8.GetBytes("1234abcd");
        private static readonly byte[] SampleKeyData = Encoding.UTF8.GetBytes("secret_key");
        private static readonly byte[] EmptyData = Array.Empty<byte>();
        private static readonly byte[] EmptyKeyData = Array.Empty<byte>();
        
        private const string SampleText = "1234abcd";
        private const string SampleKey = "secret_key";
        private const string EmptyText = "";
        private const string EmptyKey = "";

        #region Helper Methods for Expected Values
        private static string ComputeExpectedHex(string plainText, string key, bool toUppercase = true)
        {
            using var hmac = new HMACMD5(Encoding.UTF8.GetBytes(key));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(plainText));
            var hex = BitConverter.ToString(hash).Replace("-", "");
            return toUppercase ? hex.ToUpper() : hex.ToLower();
        }

        private static string ComputeExpectedBase64(string plainText, string key)
        {
            using var hmac = new HMACMD5(Encoding.UTF8.GetBytes(key));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(plainText));
            return Convert.ToBase64String(hash);
        }

        private static string ComputeExpectedBase64Substring(string plainText, string key)
        {
            using var hmac = new HMACMD5(Encoding.UTF8.GetBytes(key));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(plainText));
            var subHash = new byte[hash.Length / 2];
            Array.Copy(hash, 4, subHash, 0, 8);
            return Convert.ToBase64String(subHash);
        }
        #endregion

        [Test]
        public void ComputeHmacMd5Hash_ValidData_ReturnsCorrectHashLength()
        {
            var hash = HmacMd5CryptoUtility.ComputeHash(SampleData, SampleKeyData);
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHmacMd5Hash_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(null!, SampleKeyData));
        }

        [Test]
        public void ComputeHmacMd5Hash_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(SampleData, null!));
        }

        [Test]
        public void ComputeHmacMd5Hash_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(EmptyData, SampleKeyData));
        }

        [Test]
        public void ComputeHmacMd5Hash_EmptyKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(SampleData, EmptyKeyData));
        }

        [Test]
        public void ComputeHash_ValidString_ReturnsCorrectHashLength()
        {
            var hash = HmacMd5CryptoUtility.ComputeHash(SampleText, SampleKey);
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHash_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(null!, SampleKey));
        }

        [Test]
        public void ComputeHash_NullKeyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(SampleText, null!));
        }

        [Test]
        public void ComputeHash_EmptyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(EmptyText, SampleKey));
        }

        [Test]
        public void ComputeHash_EmptyKeyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHash(SampleText, EmptyKey));
        }

        [Test]
        public void ComputeHash_StringWithUTF8Encoding_ReturnsCorrectHash()
        {
            var hash = HmacMd5CryptoUtility.ComputeHash(SampleText, SampleKey, Encoding.UTF8);
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHashToHexString_ValidData_DefaultUppercase_ReturnsCorrectFormat()
        {
            var expected = ComputeExpectedHex(SampleText, SampleKey);
            var actual = HmacMd5CryptoUtility.ComputeHashToHexString(SampleData, SampleKeyData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(32, actual.Length);
        }

        [Test]
        public void ComputeHashToHexString_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            var expected = ComputeExpectedHex(SampleText, SampleKey, false);
            var actual = HmacMd5CryptoUtility.ComputeHashToHexString(SampleData, SampleKeyData, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHashToHexString_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHashToHexString((byte[])null!, SampleKeyData));
        }

        [Test]
        public void ComputeHashToHexString_ValidString_DefaultUppercase_ReturnsCorrectFormat()
        {
            var expected = ComputeExpectedHex(SampleText, SampleKey);
            var actual = HmacMd5CryptoUtility.ComputeHashToHexString(SampleText, SampleKey);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(32, actual.Length);
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidData_DefaultUppercase_ReturnsCorrectSubstring()
        {
            var fullHex = ComputeExpectedHex(SampleText, SampleKey);
            var expected = fullHex.Substring(8, 16);
            var actual = HmacMd5CryptoUtility.ComputeHashToHexSubstring(SampleData, SampleKeyData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            var fullHex = ComputeExpectedHex(SampleText, SampleKey, false);
            var expected = fullHex.Substring(8, 16);
            var actual = HmacMd5CryptoUtility.ComputeHashToHexSubstring(SampleData, SampleKeyData, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHashToHexSubstring_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHashToHexSubstring((byte[])null!, SampleKeyData));
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidString_DefaultUppercase_ReturnsCorrectSubstring()
        {
            var fullHex = ComputeExpectedHex(SampleText, SampleKey);
            var expected = fullHex.Substring(8, 16);
            var actual = HmacMd5CryptoUtility.ComputeHashToHexSubstring(SampleText, SampleKey);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64String_ValidData_ReturnsCorrectFormat()
        {
            var expected = ComputeExpectedBase64(SampleText, SampleKey);
            var actual = HmacMd5CryptoUtility.ComputeHashToBase64String(SampleData, SampleKeyData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(24, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64String_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHashToBase64String(null!, SampleKeyData));
        }

        [Test]
        public void ComputeHashToBase64String_ValidString_ReturnsCorrectFormat()
        {
            var expected = ComputeExpectedBase64(SampleText, SampleKey);
            var actual = HmacMd5CryptoUtility.ComputeHashToBase64String(SampleText, SampleKey);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(24, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64String_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHashToBase64String(null!, SampleKey));
        }

        [Test]
        public void ComputeHashToBase64Substring_ValidData_ReturnsCorrectFormat()
        {
            var expected = ComputeExpectedBase64Substring(SampleText, SampleKey);
            var actual = HmacMd5CryptoUtility.ComputeHashToBase64Substring(SampleData, SampleKeyData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(12, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHashToBase64Substring(null!, SampleKeyData));
        }

        [Test]
        public void ComputeHashToBase64Substring_ValidString_ReturnsCorrectFormat()
        {
            var expected = ComputeExpectedBase64Substring(SampleText, SampleKey);
            var actual = HmacMd5CryptoUtility.ComputeHashToBase64Substring(SampleText, SampleKey);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(12, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => HmacMd5CryptoUtility.ComputeHashToBase64Substring(null!, SampleKey));
        }

        [Test]
        public void ComputeHashToBase64String_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = HmacMd5CryptoUtility.ComputeHashToBase64String(largeData, SampleKeyData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(24, result.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = HmacMd5CryptoUtility.ComputeHashToBase64Substring(largeData, SampleKeyData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(12, result.Length);
        }

        [Test]
        public void ComputeHmacMd5Hash_LargeData_ReturnsValidHash()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hash = HmacMd5CryptoUtility.ComputeHash(largeData, SampleKeyData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }
    }
}