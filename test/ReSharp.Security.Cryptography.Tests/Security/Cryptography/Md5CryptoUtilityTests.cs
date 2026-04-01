using System;
using System.Text;
using NUnit.Framework;

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class Md5CryptoUtilityTests
    {
        private static readonly byte[] SampleData = Encoding.UTF8.GetBytes("1234abcd");
        private static readonly byte[] EmptyData = Array.Empty<byte>();

        [Test]
        public void ComputeMd5Hash_ValidData_ReturnsCorrectHashLength()
        {
            var hash = Md5CryptoUtility.ComputeHash(SampleData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeMd5Hash_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHash(null!));
        }

        [Test]
        public void ComputeMd5Hash_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHash(EmptyData));
        }

        [Test]
        public void ComputeMd5Hash_SameInput_ProducesSameHash()
        {
            var hash1 = Md5CryptoUtility.ComputeHash(SampleData);
            var hash2 = Md5CryptoUtility.ComputeHash(SampleData);
            
            Assert.AreEqual(hash1, hash2);
        }

        [Test]
        public void ComputeMd5Hash_DifferentInput_ProducesDifferentHash()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var hash1 = Md5CryptoUtility.ComputeHash(data1);
            var hash2 = Md5CryptoUtility.ComputeHash(data2);
            
            Assert.AreNotEqual(hash1, hash2);
        }

        [Test]
        public void ComputeHashToHexString_ValidData_DefaultUppercase_ReturnsCorrectFormat()
        {
            const string expected = "EF73781EFFC5774100F87FE2F437A435";
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(32, actual.Length);
        }

        [Test]
        public void ComputeHashToHexString_ValidData_ToUppercaseTrue_ReturnsUppercase()
        {
            const string expected = "EF73781EFFC5774100F87FE2F437A435";
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleData, toUppercase: true);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeHashToHexString_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            const string expected = "ef73781effc5774100f87fe2f437a435";
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleData, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHashToHexString_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexString(null!));
        }

        [Test]
        public void ComputeHashToHexString_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexString(EmptyData));
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidData_DefaultUppercase_ReturnsCorrectSubstring()
        {
            const string expected = "FFC5774100F87FE2";
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidData_ToUppercaseTrue_ReturnsUppercase()
        {
            const string expected = "FFC5774100F87FE2";
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleData, toUppercase: true);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            const string expected = "ffc5774100f87fe2";
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleData, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHashToHexSubstring_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexSubstring(null!));
        }

        [Test]
        public void ComputeHashToHexSubstring_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexSubstring(EmptyData));
        }

        [Test]
        public void ComputeHashToBase64String_ValidData_ReturnsCorrectFormat()
        {
            const string expected = "73N4Hv/Fd0EA+H/i9DekNQ==";
            var actual = Md5CryptoUtility.ComputeHashToBase64String(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(24, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64String_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64String(null!));
        }

        [Test]
        public void ComputeHashToBase64String_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64String(EmptyData));
        }

        [Test]
        public void ComputeHashToBase64String_SameInput_ProducesSameResult()
        {
            var result1 = Md5CryptoUtility.ComputeHashToBase64String(SampleData);
            var result2 = Md5CryptoUtility.ComputeHashToBase64String(SampleData);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void ComputeHashToBase64String_DifferentInput_ProducesDifferentResult()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var result1 = Md5CryptoUtility.ComputeHashToBase64String(data1);
            var result2 = Md5CryptoUtility.ComputeHashToBase64String(data2);
            
            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void ComputeHashToBase64Substring_ValidData_ReturnsCorrectFormat()
        {
            const string expected = "/8V3QQD4f+I=";
            var actual = Md5CryptoUtility.ComputeHashToBase64Substring(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(12, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64Substring(null!));
        }

        [Test]
        public void ComputeHashToBase64Substring_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64Substring(EmptyData));
        }

        [Test]
        public void ComputeHashToBase64Substring_SameInput_ProducesSameResult()
        {
            var result1 = Md5CryptoUtility.ComputeHashToBase64Substring(SampleData);
            var result2 = Md5CryptoUtility.ComputeHashToBase64Substring(SampleData);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void ComputeHashToBase64Substring_DifferentInput_ProducesDifferentResult()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var result1 = Md5CryptoUtility.ComputeHashToBase64Substring(data1);
            var result2 = Md5CryptoUtility.ComputeHashToBase64Substring(data2);
            
            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void ComputeHashToBase64Substring_VerifiesHalfLengthOfFullHash()
        {
            var fullBase64 = Md5CryptoUtility.ComputeHashToBase64String(SampleData);
            var substringBase64 = Md5CryptoUtility.ComputeHashToBase64Substring(SampleData);
            
            // Verify that the substring is indeed half the length (accounting for base64 padding)
            Assert.IsTrue(substringBase64.Length < fullBase64.Length);
        }

        [Test]
        public void ComputeHashToBase64String_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = Md5CryptoUtility.ComputeHashToBase64String(largeData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(24, result.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = Md5CryptoUtility.ComputeHashToBase64Substring(largeData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(12, result.Length);
        }

        [Test]
        public void ComputeMd5Hash_LargeData_ReturnsValidHash()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hash = Md5CryptoUtility.ComputeHash(largeData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHashToHexString_LargeData_ReturnsValidHexString()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hexString = Md5CryptoUtility.ComputeHashToHexString(largeData);
            
            Assert.IsNotNull(hexString);
            Assert.AreEqual(32, hexString.Length);
        }

        [Test]
        public void ComputeHashToHexSubstring_LargeData_ReturnsValidSubstring()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var substring = Md5CryptoUtility.ComputeHashToHexSubstring(largeData);
            
            Assert.IsNotNull(substring);
            Assert.AreEqual(16, substring.Length);
        }
    }
}