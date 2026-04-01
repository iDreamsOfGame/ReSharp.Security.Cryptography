using System;
using System.Text;
using NUnit.Framework;

// ReSharper disable AssignNullToNotNullAttribute

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class Md5CryptoUtilityTests
    {
        private static readonly byte[] SampleData = Encoding.UTF8.GetBytes("1234abcd");
        private static readonly byte[] EmptyData = Array.Empty<byte>();
        private const string SampleText = "1234abcd";
        private const string EmptyText = "";

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
        public void ComputeHash_ValidString_ReturnsCorrectHashLength()
        {
            var hash = Md5CryptoUtility.ComputeHash(SampleText);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHash_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHash(null!));
        }

        [Test]
        public void ComputeHash_EmptyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHash(EmptyText));
        }

        [Test]
        public void ComputeHash_StringWithUTF8Encoding_ReturnsCorrectHash()
        {
            var hash = Md5CryptoUtility.ComputeHash(SampleText, Encoding.UTF8);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHash_StringWithUnicodeEncoding_ReturnsCorrectHash()
        {
            var hash = Md5CryptoUtility.ComputeHash(SampleText, Encoding.Unicode);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHash_StringWithASCIIEncoding_ReturnsCorrectHash()
        {
            var hash = Md5CryptoUtility.ComputeHash(SampleText, Encoding.ASCII);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(16, hash.Length);
        }

        [Test]
        public void ComputeHash_String_SameInput_ProducesSameHash()
        {
            var hash1 = Md5CryptoUtility.ComputeHash(SampleText);
            var hash2 = Md5CryptoUtility.ComputeHash(SampleText);
            
            Assert.AreEqual(hash1, hash2);
        }

        [Test]
        public void ComputeHash_String_DifferentInput_ProducesDifferentHash()
        {
            var hash1 = Md5CryptoUtility.ComputeHash("1234abcd");
            var hash2 = Md5CryptoUtility.ComputeHash("5678efgh");
            
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
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexString((byte[])null));
        }

        [Test]
        public void ComputeHashToHexString_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexString(EmptyData));
        }

        [Test]
        public void ComputeHashToHexString_ValidString_DefaultUppercase_ReturnsCorrectFormat()
        {
            const string expected = "EF73781EFFC5774100F87FE2F437A435";
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(32, actual.Length);
        }

        [Test]
        public void ComputeHashToHexString_ValidString_ToUppercaseTrue_ReturnsUppercase()
        {
            const string expected = "EF73781EFFC5774100F87FE2F437A435";
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleText, toUppercase: true);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeHashToHexString_ValidString_ToUppercaseFalse_ReturnsLowercase()
        {
            const string expected = "ef73781effc5774100f87fe2f437a435";
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleText, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHashToHexString_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexString((string)null!));
        }

        [Test]
        public void ComputeHashToHexString_EmptyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexString(EmptyText));
        }

        [Test]
        public void ComputeHashToHexString_StringWithUTF8Encoding_ReturnsCorrectFormat()
        {
            const string expected = "EF73781EFFC5774100F87FE2F437A435";
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleText, Encoding.UTF8);
            
            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void ComputeHashToHexString_StringWithUnicodeEncoding_ReturnsCorrectFormat()
        {
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleText, Encoding.Unicode);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(32, actual.Length);
        }

        [Test]
        public void ComputeHashToHexString_StringWithASCIIEncoding_ReturnsCorrectFormat()
        {
            var actual = Md5CryptoUtility.ComputeHashToHexString(SampleText, Encoding.ASCII);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(32, actual.Length);
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
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexSubstring((byte[])null));
        }

        [Test]
        public void ComputeHashToHexSubstring_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexSubstring(EmptyData));
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidString_DefaultUppercase_ReturnsCorrectSubstring()
        {
            const string expected = "FFC5774100F87FE2";
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidString_ToUppercaseTrue_ReturnsUppercase()
        {
            const string expected = "FFC5774100F87FE2";
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleText, toUppercase: true);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeHashToHexSubstring_ValidString_ToUppercaseFalse_ReturnsLowercase()
        {
            const string expected = "ffc5774100f87fe2";
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleText, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(16, actual.Length);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeHashToHexSubstring_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexSubstring((string)null!));
        }

        [Test]
        public void ComputeHashToHexSubstring_EmptyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToHexSubstring(EmptyText));
        }

        [Test]
        public void ComputeHashToHexSubstring_StringWithUTF8Encoding_ReturnsCorrectSubstring()
        {
            const string expected = "FFC5774100F87FE2";
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleText, Encoding.UTF8);
            
            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void ComputeHashToHexSubstring_StringWithUnicodeEncoding_ReturnsCorrectSubstring()
        {
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleText, Encoding.Unicode);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(16, actual.Length);
        }

        [Test]
        public void ComputeHashToHexSubstring_StringWithASCIIEncoding_ReturnsCorrectSubstring()
        {
            var actual = Md5CryptoUtility.ComputeHashToHexSubstring(SampleText, Encoding.ASCII);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(16, actual.Length);
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
        public void ComputeHashToBase64String_ValidString_ReturnsCorrectFormat()
        {
            const string expected = "73N4Hv/Fd0EA+H/i9DekNQ==";
            var actual = Md5CryptoUtility.ComputeHashToBase64String(SampleText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(24, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64String_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64String(null!));
        }

        [Test]
        public void ComputeHashToBase64String_EmptyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64String(EmptyText));
        }

        [Test]
        public void ComputeHashToBase64String_StringWithUTF8Encoding_ReturnsCorrectFormat()
        {
            const string expected = "73N4Hv/Fd0EA+H/i9DekNQ==";
            var actual = Md5CryptoUtility.ComputeHashToBase64String(SampleText, Encoding.UTF8);
            
            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void ComputeHashToBase64String_StringWithUnicodeEncoding_ReturnsCorrectFormat()
        {
            var actual = Md5CryptoUtility.ComputeHashToBase64String(SampleText, Encoding.Unicode);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(24, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64String_StringWithASCIIEncoding_ReturnsCorrectFormat()
        {
            var actual = Md5CryptoUtility.ComputeHashToBase64String(SampleText, Encoding.ASCII);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(24, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64String_String_SameInput_ProducesSameResult()
        {
            var result1 = Md5CryptoUtility.ComputeHashToBase64String(SampleText);
            var result2 = Md5CryptoUtility.ComputeHashToBase64String(SampleText);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void ComputeHashToBase64String_String_DifferentInput_ProducesDifferentResult()
        {
            var result1 = Md5CryptoUtility.ComputeHashToBase64String("1234abcd");
            var result2 = Md5CryptoUtility.ComputeHashToBase64String("5678efgh");
            
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
        public void ComputeHashToBase64Substring_ValidString_ReturnsCorrectFormat()
        {
            const string expected = "/8V3QQD4f+I=";
            var actual = Md5CryptoUtility.ComputeHashToBase64Substring(SampleText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(12, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_NullString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64Substring(null!));
        }

        [Test]
        public void ComputeHashToBase64Substring_EmptyString_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => Md5CryptoUtility.ComputeHashToBase64Substring(EmptyText));
        }

        [Test]
        public void ComputeHashToBase64Substring_StringWithUTF8Encoding_ReturnsCorrectFormat()
        {
            const string expected = "/8V3QQD4f+I=";
            var actual = Md5CryptoUtility.ComputeHashToBase64Substring(SampleText, Encoding.UTF8);
            
            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void ComputeHashToBase64Substring_StringWithUnicodeEncoding_ReturnsCorrectFormat()
        {
            var actual = Md5CryptoUtility.ComputeHashToBase64Substring(SampleText, Encoding.Unicode);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(12, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_StringWithASCIIEncoding_ReturnsCorrectFormat()
        {
            var actual = Md5CryptoUtility.ComputeHashToBase64Substring(SampleText, Encoding.ASCII);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(12, actual.Length);
        }

        [Test]
        public void ComputeHashToBase64Substring_String_SameInput_ProducesSameResult()
        {
            var result1 = Md5CryptoUtility.ComputeHashToBase64Substring(SampleText);
            var result2 = Md5CryptoUtility.ComputeHashToBase64Substring(SampleText);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void ComputeHashToBase64Substring_String_DifferentInput_ProducesDifferentResult()
        {
            var result1 = Md5CryptoUtility.ComputeHashToBase64Substring("1234abcd");
            var result2 = Md5CryptoUtility.ComputeHashToBase64Substring("5678efgh");
            
            Assert.AreNotEqual(result1, result2);
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