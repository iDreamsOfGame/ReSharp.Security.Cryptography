using System;
using System.Text;
using NUnit.Framework;

// ReSharper disable AssignNullToNotNullAttribute

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class ShaCryptoUtilityTests
    {
        private static readonly byte[] SampleData = Encoding.UTF8.GetBytes("1234abcd");
        private static readonly byte[] EmptyData = Array.Empty<byte>();

        #region SHA1 Tests

        [Test]
        public void ComputeSha1Hash_ValidData_ReturnsCorrectHashLength()
        {
            var hash = ShaCryptoUtility.ComputeSha1Hash(SampleData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(20, hash.Length);
        }

        [Test]
        public void ComputeSha1Hash_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1Hash(null!));
        }

        [Test]
        public void ComputeSha1Hash_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1Hash(EmptyData));
        }

        [Test]
        public void ComputeSha1Hash_SameInput_ProducesSameHash()
        {
            var hash1 = ShaCryptoUtility.ComputeSha1Hash(SampleData);
            var hash2 = ShaCryptoUtility.ComputeSha1Hash(SampleData);
            
            Assert.AreEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha1Hash_DifferentInput_ProducesDifferentHash()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var hash1 = ShaCryptoUtility.ComputeSha1Hash(data1);
            var hash2 = ShaCryptoUtility.ComputeSha1Hash(data2);
            
            Assert.AreNotEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha1HashToHexString_ValidData_DefaultUppercase_ReturnsCorrectFormat()
        {
            const string expected = "E7D537E128158790157EA057BB883E0292A84930";
            var actual = ShaCryptoUtility.ComputeSha1HashToHexString(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(40, actual.Length);
        }

        [Test]
        public void ComputeSha1HashToHexString_ValidData_ToUppercaseTrue_ReturnsUppercase()
        {
            const string expected = "E7D537E128158790157EA057BB883E0292A84930";
            var actual = ShaCryptoUtility.ComputeSha1HashToHexString(SampleData, toUppercase: true);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeSha1HashToHexString_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            const string expected = "e7d537e128158790157ea057bb883e0292a84930";
            var actual = ShaCryptoUtility.ComputeSha1HashToHexString(SampleData, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeSha1HashToHexString_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1HashToHexString((byte[])null));
        }

        [Test]
        public void ComputeSha1HashToHexString_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1HashToHexString(EmptyData));
        }

        [Test]
        public void ComputeSha1HashToBase64String_ValidData_ReturnsCorrectFormat()
        {
            const string expected = "59U34SgVh5AVfqBXu4g+ApKoSTA=";
            var actual = ShaCryptoUtility.ComputeSha1HashToBase64String(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(28, actual.Length);
        }

        [Test]
        public void ComputeSha1HashToBase64String_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1HashToBase64String(null!));
        }

        [Test]
        public void ComputeSha1HashToBase64String_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1HashToBase64String(EmptyData));
        }

        [Test]
        public void ComputeSha1HashToBase64String_SameInput_ProducesSameResult()
        {
            var result1 = ShaCryptoUtility.ComputeSha1HashToBase64String(SampleData);
            var result2 = ShaCryptoUtility.ComputeSha1HashToBase64String(SampleData);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void ComputeSha1HashToBase64String_DifferentInput_ProducesDifferentResult()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var result1 = ShaCryptoUtility.ComputeSha1HashToBase64String(data1);
            var result2 = ShaCryptoUtility.ComputeSha1HashToBase64String(data2);
            
            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void ComputeSha1Hash_LargeData_ReturnsValidHash()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hash = ShaCryptoUtility.ComputeSha1Hash(largeData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(20, hash.Length);
        }

        [Test]
        public void ComputeSha1HashToHexString_LargeData_ReturnsValidHexString()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hexString = ShaCryptoUtility.ComputeSha1HashToHexString(largeData);
            
            Assert.IsNotNull(hexString);
            Assert.AreEqual(40, hexString.Length);
        }

        [Test]
        public void ComputeSha1HashToBase64String_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = ShaCryptoUtility.ComputeSha1HashToBase64String(largeData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(28, result.Length);
        }

        [Test]
        public void ComputeSha1Hash_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var hash = ShaCryptoUtility.ComputeSha1Hash(plainText);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(20, hash.Length);
        }

        [Test]
        public void ComputeSha1Hash_StringParameter_NullText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1Hash((string)null!));
        }

        [Test]
        public void ComputeSha1Hash_StringParameter_EmptyText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha1Hash(string.Empty));
        }

        [Test]
        public void ComputeSha1Hash_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hashUtf8 = ShaCryptoUtility.ComputeSha1Hash(plainText, Encoding.UTF8);
            var hashUnicode = ShaCryptoUtility.ComputeSha1Hash(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hashUtf8);
            Assert.IsNotNull(hashUnicode);
            Assert.AreEqual(20, hashUtf8.Length);
            Assert.AreEqual(20, hashUnicode.Length);
            Assert.AreNotEqual(hashUtf8, hashUnicode);
        }

        [Test]
        public void ComputeSha1HashToHexString_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            const string expected = "E7D537E128158790157EA057BB883E0292A84930";
            var actual = ShaCryptoUtility.ComputeSha1HashToHexString(plainText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(40, actual.Length);
        }

        [Test]
        public void ComputeSha1HashToHexString_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hexUtf8 = ShaCryptoUtility.ComputeSha1HashToHexString(plainText, Encoding.UTF8);
            var hexUnicode = ShaCryptoUtility.ComputeSha1HashToHexString(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hexUtf8);
            Assert.IsNotNull(hexUnicode);
            Assert.AreEqual(40, hexUtf8.Length);
            Assert.AreEqual(40, hexUnicode.Length);
            Assert.AreNotEqual(hexUtf8, hexUnicode);
        }

        [Test]
        public void ComputeSha1HashToBase64String_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            const string expected = "59U34SgVh5AVfqBXu4g+ApKoSTA=";
            var actual = ShaCryptoUtility.ComputeSha1HashToBase64String(plainText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(28, actual.Length);
        }

        [Test]
        public void ComputeSha1HashToBase64String_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var base64Utf8 = ShaCryptoUtility.ComputeSha1HashToBase64String(plainText, Encoding.UTF8);
            var base64Unicode = ShaCryptoUtility.ComputeSha1HashToBase64String(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(base64Utf8);
            Assert.IsNotNull(base64Unicode);
            Assert.AreNotEqual(base64Utf8, base64Unicode);
        }

        #endregion

        #region SHA256 Tests

        [Test]
        public void ComputeSha256Hash_ValidData_ReturnsCorrectHashLength()
        {
            var hash = ShaCryptoUtility.ComputeSha256Hash(SampleData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(32, hash.Length);
        }

        [Test]
        public void ComputeSha256Hash_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256Hash(null!));
        }

        [Test]
        public void ComputeSha256Hash_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256Hash(EmptyData));
        }

        [Test]
        public void ComputeSha256Hash_SameInput_ProducesSameHash()
        {
            var hash1 = ShaCryptoUtility.ComputeSha256Hash(SampleData);
            var hash2 = ShaCryptoUtility.ComputeSha256Hash(SampleData);
            
            Assert.AreEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha256Hash_DifferentInput_ProducesDifferentHash()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var hash1 = ShaCryptoUtility.ComputeSha256Hash(data1);
            var hash2 = ShaCryptoUtility.ComputeSha256Hash(data2);
            
            Assert.AreNotEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha256HashToHexString_ValidData_DefaultUppercase_ReturnsCorrectFormat()
        {
            const string expected = "221B37FCDB52D0F7C39BBD0BE211DB0E1C00CA5FBECD5788780463026C6B964B";
            var actual = ShaCryptoUtility.ComputeSha256HashToHexString(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(64, actual.Length);
        }

        [Test]
        public void ComputeSha256HashToHexString_ValidData_ToUppercaseTrue_ReturnsUppercase()
        {
            const string expected = "221B37FCDB52D0F7C39BBD0BE211DB0E1C00CA5FBECD5788780463026C6B964B";
            var actual = ShaCryptoUtility.ComputeSha256HashToHexString(SampleData, toUppercase: true);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeSha256HashToHexString_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            const string expected = "221b37fcdb52d0f7c39bbd0be211db0e1c00ca5fbecd5788780463026c6b964b";
            var actual = ShaCryptoUtility.ComputeSha256HashToHexString(SampleData, toUppercase: false);
            
            Assert.AreEqual(expected, actual);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeSha256HashToHexString_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256HashToHexString((byte[])null));
        }

        [Test]
        public void ComputeSha256HashToHexString_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256HashToHexString(EmptyData));
        }

        [Test]
        public void ComputeSha256HashToBase64String_ValidData_ReturnsCorrectFormat()
        {
            const string expected = "Ihs3/NtS0PfDm70L4hHbDhwAyl++zVeIeARjAmxrlks=";
            var actual = ShaCryptoUtility.ComputeSha256HashToBase64String(SampleData);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(44, actual.Length);
        }

        [Test]
        public void ComputeSha256HashToBase64String_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256HashToBase64String(null!));
        }

        [Test]
        public void ComputeSha256HashToBase64String_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256HashToBase64String(EmptyData));
        }

        [Test]
        public void ComputeSha256HashToBase64String_SameInput_ProducesSameResult()
        {
            var result1 = ShaCryptoUtility.ComputeSha256HashToBase64String(SampleData);
            var result2 = ShaCryptoUtility.ComputeSha256HashToBase64String(SampleData);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void ComputeSha256HashToBase64String_DifferentInput_ProducesDifferentResult()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var result1 = ShaCryptoUtility.ComputeSha256HashToBase64String(data1);
            var result2 = ShaCryptoUtility.ComputeSha256HashToBase64String(data2);
            
            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void ComputeSha256Hash_LargeData_ReturnsValidHash()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hash = ShaCryptoUtility.ComputeSha256Hash(largeData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(32, hash.Length);
        }

        [Test]
        public void ComputeSha256HashToHexString_LargeData_ReturnsValidHexString()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hexString = ShaCryptoUtility.ComputeSha256HashToHexString(largeData);
            
            Assert.IsNotNull(hexString);
            Assert.AreEqual(64, hexString.Length);
        }

        [Test]
        public void ComputeSha256HashToBase64String_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = ShaCryptoUtility.ComputeSha256HashToBase64String(largeData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(44, result.Length);
        }

        [Test]
        public void ComputeSha256Hash_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var hash = ShaCryptoUtility.ComputeSha256Hash(plainText);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(32, hash.Length);
        }

        [Test]
        public void ComputeSha256Hash_StringParameter_NullText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256Hash((string)null!));
        }

        [Test]
        public void ComputeSha256Hash_StringParameter_EmptyText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha256Hash(string.Empty));
        }

        [Test]
        public void ComputeSha256Hash_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hashUtf8 = ShaCryptoUtility.ComputeSha256Hash(plainText, Encoding.UTF8);
            var hashUnicode = ShaCryptoUtility.ComputeSha256Hash(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hashUtf8);
            Assert.IsNotNull(hashUnicode);
            Assert.AreEqual(32, hashUtf8.Length);
            Assert.AreEqual(32, hashUnicode.Length);
            Assert.AreNotEqual(hashUtf8, hashUnicode);
        }

        [Test]
        public void ComputeSha256HashToHexString_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            const string expected = "221B37FCDB52D0F7C39BBD0BE211DB0E1C00CA5FBECD5788780463026C6B964B";
            var actual = ShaCryptoUtility.ComputeSha256HashToHexString(plainText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(64, actual.Length);
        }

        [Test]
        public void ComputeSha256HashToHexString_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hexUtf8 = ShaCryptoUtility.ComputeSha256HashToHexString(plainText, Encoding.UTF8);
            var hexUnicode = ShaCryptoUtility.ComputeSha256HashToHexString(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hexUtf8);
            Assert.IsNotNull(hexUnicode);
            Assert.AreEqual(64, hexUtf8.Length);
            Assert.AreEqual(64, hexUnicode.Length);
            Assert.AreNotEqual(hexUtf8, hexUnicode);
        }

        [Test]
        public void ComputeSha256HashToBase64String_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            const string expected = "Ihs3/NtS0PfDm70L4hHbDhwAyl++zVeIeARjAmxrlks=";
            var actual = ShaCryptoUtility.ComputeSha256HashToBase64String(plainText);
            
            Assert.AreEqual(expected, actual);
            Assert.AreEqual(44, actual.Length);
        }

        [Test]
        public void ComputeSha256HashToBase64String_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var base64Utf8 = ShaCryptoUtility.ComputeSha256HashToBase64String(plainText, Encoding.UTF8);
            var base64Unicode = ShaCryptoUtility.ComputeSha256HashToBase64String(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(base64Utf8);
            Assert.IsNotNull(base64Unicode);
            Assert.AreNotEqual(base64Utf8, base64Unicode);
        }

        #endregion

        #region SHA384 Tests

        [Test]
        public void ComputeSha384Hash_ValidData_ReturnsCorrectHashLength()
        {
            var hash = ShaCryptoUtility.ComputeSha384Hash(SampleData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(48, hash.Length);
        }

        [Test]
        public void ComputeSha384Hash_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384Hash(null!));
        }

        [Test]
        public void ComputeSha384Hash_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384Hash(EmptyData));
        }

        [Test]
        public void ComputeSha384Hash_SameInput_ProducesSameHash()
        {
            var hash1 = ShaCryptoUtility.ComputeSha384Hash(SampleData);
            var hash2 = ShaCryptoUtility.ComputeSha384Hash(SampleData);
            
            Assert.AreEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha384Hash_DifferentInput_ProducesDifferentHash()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var hash1 = ShaCryptoUtility.ComputeSha384Hash(data1);
            var hash2 = ShaCryptoUtility.ComputeSha384Hash(data2);
            
            Assert.AreNotEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha384HashToHexString_ValidData_DefaultUppercase_ReturnsCorrectFormat()
        {
            var actual = ShaCryptoUtility.ComputeSha384HashToHexString(SampleData);
            Assert.AreEqual(96, actual.Length);
        }

        [Test]
        public void ComputeSha384HashToHexString_ValidData_ToUppercaseTrue_ReturnsUppercase()
        {
            var actual = ShaCryptoUtility.ComputeSha384HashToHexString(SampleData, toUppercase: true);
            
            Assert.AreEqual(96, actual.Length);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeSha384HashToHexString_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            var actual = ShaCryptoUtility.ComputeSha384HashToHexString(SampleData, toUppercase: false);
            
            Assert.AreEqual(96, actual.Length);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeSha384HashToHexString_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384HashToHexString((byte[])null));
        }

        [Test]
        public void ComputeSha384HashToHexString_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384HashToHexString(EmptyData));
        }

        [Test]
        public void ComputeSha384HashToBase64String_ValidData_ReturnsCorrectFormat()
        {
            var actual = ShaCryptoUtility.ComputeSha384HashToBase64String(SampleData);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(64, actual.Length);
        }

        [Test]
        public void ComputeSha384HashToBase64String_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384HashToBase64String(null!));
        }

        [Test]
        public void ComputeSha384HashToBase64String_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384HashToBase64String(EmptyData));
        }

        [Test]
        public void ComputeSha384HashToBase64String_SameInput_ProducesSameResult()
        {
            var result1 = ShaCryptoUtility.ComputeSha384HashToBase64String(SampleData);
            var result2 = ShaCryptoUtility.ComputeSha384HashToBase64String(SampleData);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void ComputeSha384HashToBase64String_DifferentInput_ProducesDifferentResult()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var result1 = ShaCryptoUtility.ComputeSha384HashToBase64String(data1);
            var result2 = ShaCryptoUtility.ComputeSha384HashToBase64String(data2);
            
            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void ComputeSha384Hash_LargeData_ReturnsValidHash()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hash = ShaCryptoUtility.ComputeSha384Hash(largeData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(48, hash.Length);
        }

        [Test]
        public void ComputeSha384HashToHexString_LargeData_ReturnsValidHexString()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hexString = ShaCryptoUtility.ComputeSha384HashToHexString(largeData);
            
            Assert.IsNotNull(hexString);
            Assert.AreEqual(96, hexString.Length);
        }

        [Test]
        public void ComputeSha384HashToBase64String_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = ShaCryptoUtility.ComputeSha384HashToBase64String(largeData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(64, result.Length);
        }

        [Test]
        public void ComputeSha384Hash_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var hash = ShaCryptoUtility.ComputeSha384Hash(plainText);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(48, hash.Length);
        }

        [Test]
        public void ComputeSha384Hash_StringParameter_NullText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384Hash((string)null!));
        }

        [Test]
        public void ComputeSha384Hash_StringParameter_EmptyText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha384Hash(string.Empty));
        }

        [Test]
        public void ComputeSha384Hash_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hashUtf8 = ShaCryptoUtility.ComputeSha384Hash(plainText, Encoding.UTF8);
            var hashUnicode = ShaCryptoUtility.ComputeSha384Hash(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hashUtf8);
            Assert.IsNotNull(hashUnicode);
            Assert.AreEqual(48, hashUtf8.Length);
            Assert.AreEqual(48, hashUnicode.Length);
            Assert.AreNotEqual(hashUtf8, hashUnicode);
        }

        [Test]
        public void ComputeSha384HashToHexString_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var actual = ShaCryptoUtility.ComputeSha384HashToHexString(plainText);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(96, actual.Length);
        }

        [Test]
        public void ComputeSha384HashToHexString_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hexUtf8 = ShaCryptoUtility.ComputeSha384HashToHexString(plainText, Encoding.UTF8);
            var hexUnicode = ShaCryptoUtility.ComputeSha384HashToHexString(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hexUtf8);
            Assert.IsNotNull(hexUnicode);
            Assert.AreEqual(96, hexUtf8.Length);
            Assert.AreEqual(96, hexUnicode.Length);
            Assert.AreNotEqual(hexUtf8, hexUnicode);
        }

        [Test]
        public void ComputeSha384HashToBase64String_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var actual = ShaCryptoUtility.ComputeSha384HashToBase64String(plainText);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(64, actual.Length);
        }

        [Test]
        public void ComputeSha384HashToBase64String_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var base64Utf8 = ShaCryptoUtility.ComputeSha384HashToBase64String(plainText, Encoding.UTF8);
            var base64Unicode = ShaCryptoUtility.ComputeSha384HashToBase64String(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(base64Utf8);
            Assert.IsNotNull(base64Unicode);
            Assert.AreNotEqual(base64Utf8, base64Unicode);
        }

        #endregion

        #region SHA512 Tests

        [Test]
        public void ComputeSha512Hash_ValidData_ReturnsCorrectHashLength()
        {
            var hash = ShaCryptoUtility.ComputeSha512Hash(SampleData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(64, hash.Length);
        }

        [Test]
        public void ComputeSha512Hash_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512Hash(null!));
        }

        [Test]
        public void ComputeSha512Hash_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512Hash(EmptyData));
        }

        [Test]
        public void ComputeSha512Hash_SameInput_ProducesSameHash()
        {
            var hash1 = ShaCryptoUtility.ComputeSha512Hash(SampleData);
            var hash2 = ShaCryptoUtility.ComputeSha512Hash(SampleData);
            
            Assert.AreEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha512Hash_DifferentInput_ProducesDifferentHash()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var hash1 = ShaCryptoUtility.ComputeSha512Hash(data1);
            var hash2 = ShaCryptoUtility.ComputeSha512Hash(data2);
            
            Assert.AreNotEqual(hash1, hash2);
        }

        [Test]
        public void ComputeSha512HashToHexString_ValidData_DefaultUppercase_ReturnsCorrectFormat()
        {
            var actual = ShaCryptoUtility.ComputeSha512HashToHexString(SampleData);
            
            Assert.AreEqual(128, actual.Length);
        }

        [Test]
        public void ComputeSha512HashToHexString_ValidData_ToUppercaseTrue_ReturnsUppercase()
        {
            var actual = ShaCryptoUtility.ComputeSha512HashToHexString(SampleData, toUppercase: true);
            
            Assert.AreEqual(128, actual.Length);
            Assert.IsTrue(actual == actual.ToUpper());
        }

        [Test]
        public void ComputeSha512HashToHexString_ValidData_ToUppercaseFalse_ReturnsLowercase()
        {
            var actual = ShaCryptoUtility.ComputeSha512HashToHexString(SampleData, toUppercase: false);
            
            Assert.AreEqual(128, actual.Length);
            Assert.IsTrue(actual == actual.ToLower());
        }

        [Test]
        public void ComputeSha512HashToHexString_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512HashToHexString((byte[])null));
        }

        [Test]
        public void ComputeSha512HashToHexString_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512HashToHexString(EmptyData));
        }

        [Test]
        public void GenerateSha512Base64String_ValidData_ReturnsCorrectFormat()
        {
            var actual = ShaCryptoUtility.ComputeSha512HashToBase64String(SampleData);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(88, actual.Length);
        }

        [Test]
        public void GenerateSha512Base64String_NullData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512HashToBase64String(null!));
        }

        [Test]
        public void GenerateSha512Base64String_EmptyData_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512HashToBase64String(EmptyData));
        }

        [Test]
        public void GenerateSha512Base64String_SameInput_ProducesSameResult()
        {
            var result1 = ShaCryptoUtility.ComputeSha512HashToBase64String(SampleData);
            var result2 = ShaCryptoUtility.ComputeSha512HashToBase64String(SampleData);
            
            Assert.AreEqual(result1, result2);
        }

        [Test]
        public void GenerateSha512Base64String_DifferentInput_ProducesDifferentResult()
        {
            var data1 = Encoding.UTF8.GetBytes("1234abcd");
            var data2 = Encoding.UTF8.GetBytes("5678efgh");
            
            var result1 = ShaCryptoUtility.ComputeSha512HashToBase64String(data1);
            var result2 = ShaCryptoUtility.ComputeSha512HashToBase64String(data2);
            
            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void ComputeSha512Hash_LargeData_ReturnsValidHash()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hash = ShaCryptoUtility.ComputeSha512Hash(largeData);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(64, hash.Length);
        }

        [Test]
        public void ComputeSha512HashToHexString_LargeData_ReturnsValidHexString()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var hexString = ShaCryptoUtility.ComputeSha512HashToHexString(largeData);
            
            Assert.IsNotNull(hexString);
            Assert.AreEqual(128, hexString.Length);
        }

        [Test]
        public void GenerateSha512Base64String_LargeData_ReturnsValidResult()
        {
            var largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            var result = ShaCryptoUtility.ComputeSha512HashToBase64String(largeData);
            
            Assert.IsNotNull(result);
            Assert.AreEqual(88, result.Length);
        }

        [Test]
        public void ComputeSha512Hash_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var hash = ShaCryptoUtility.ComputeSha512Hash(plainText);
            
            Assert.IsNotNull(hash);
            Assert.AreEqual(64, hash.Length);
        }

        [Test]
        public void ComputeSha512Hash_StringParameter_NullText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512Hash((string)null!));
        }

        [Test]
        public void ComputeSha512Hash_StringParameter_EmptyText_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ShaCryptoUtility.ComputeSha512Hash(string.Empty));
        }

        [Test]
        public void ComputeSha512Hash_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hashUtf8 = ShaCryptoUtility.ComputeSha512Hash(plainText, Encoding.UTF8);
            var hashUnicode = ShaCryptoUtility.ComputeSha512Hash(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hashUtf8);
            Assert.IsNotNull(hashUnicode);
            Assert.AreEqual(64, hashUtf8.Length);
            Assert.AreEqual(64, hashUnicode.Length);
            Assert.AreNotEqual(hashUtf8, hashUnicode);
        }

        [Test]
        public void ComputeSha512HashToHexString_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var actual = ShaCryptoUtility.ComputeSha512HashToHexString(plainText);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(128, actual.Length);
        }

        [Test]
        public void ComputeSha512HashToHexString_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var hexUtf8 = ShaCryptoUtility.ComputeSha512HashToHexString(plainText, Encoding.UTF8);
            var hexUnicode = ShaCryptoUtility.ComputeSha512HashToHexString(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(hexUtf8);
            Assert.IsNotNull(hexUnicode);
            Assert.AreEqual(128, hexUtf8.Length);
            Assert.AreEqual(128, hexUnicode.Length);
            Assert.AreNotEqual(hexUtf8, hexUnicode);
        }

        [Test]
        public void ComputeSha512HashToBase64String_StringParameter_ValidData_ReturnsCorrectHash()
        {
            const string plainText = "1234abcd";
            var actual = ShaCryptoUtility.ComputeSha512HashToBase64String(plainText);
            
            Assert.IsNotNull(actual);
            Assert.AreEqual(88, actual.Length);
        }

        [Test]
        public void ComputeSha512HashToBase64String_StringParameter_WithEncoding_ReturnsCorrectHash()
        {
            const string plainText = "你好";
            var base64Utf8 = ShaCryptoUtility.ComputeSha512HashToBase64String(plainText, Encoding.UTF8);
            var base64Unicode = ShaCryptoUtility.ComputeSha512HashToBase64String(plainText, Encoding.Unicode);
            
            Assert.IsNotNull(base64Utf8);
            Assert.IsNotNull(base64Unicode);
            Assert.AreNotEqual(base64Utf8, base64Unicode);
        }

        #endregion

        #region Cross-Algorithm Tests

        [Test]
        public void DifferentShaAlgorithms_ProduceDifferentHashes_ForSameInput()
        {
            var sha1Hash = ShaCryptoUtility.ComputeSha1Hash(SampleData);
            var sha256Hash = ShaCryptoUtility.ComputeSha256Hash(SampleData);
            var sha384Hash = ShaCryptoUtility.ComputeSha384Hash(SampleData);
            var sha512Hash = ShaCryptoUtility.ComputeSha512Hash(SampleData);
            
            Assert.AreNotEqual(sha1Hash, sha256Hash);
            Assert.AreNotEqual(sha1Hash, sha384Hash);
            Assert.AreNotEqual(sha1Hash, sha512Hash);
            Assert.AreNotEqual(sha256Hash, sha384Hash);
            Assert.AreNotEqual(sha256Hash, sha512Hash);
            Assert.AreNotEqual(sha384Hash, sha512Hash);
        }

        [Test]
        public void ShaHashLengths_AreCorrect_ForAllAlgorithms()
        {
            var sha1Hash = ShaCryptoUtility.ComputeSha1Hash(SampleData);
            var sha256Hash = ShaCryptoUtility.ComputeSha256Hash(SampleData);
            var sha384Hash = ShaCryptoUtility.ComputeSha384Hash(SampleData);
            var sha512Hash = ShaCryptoUtility.ComputeSha512Hash(SampleData);
            
            Assert.AreEqual(20, sha1Hash.Length);   // SHA1: 160 bits = 20 bytes
            Assert.AreEqual(32, sha256Hash.Length); // SHA256: 256 bits = 32 bytes
            Assert.AreEqual(48, sha384Hash.Length); // SHA384: 384 bits = 48 bytes
            Assert.AreEqual(64, sha512Hash.Length); // SHA512: 512 bits = 64 bytes
        }

        [Test]
        public void StringParameters_ProduceSameHash_AsByteArrayParameters()
        {
            const string plainText = "1234abcd";
            
            var sha1String = ShaCryptoUtility.ComputeSha1Hash(plainText);
            var sha1Bytes = ShaCryptoUtility.ComputeSha1Hash(Encoding.UTF8.GetBytes(plainText));
            Assert.AreEqual(sha1String, sha1Bytes);
            
            var sha256String = ShaCryptoUtility.ComputeSha256Hash(plainText);
            var sha256Bytes = ShaCryptoUtility.ComputeSha256Hash(Encoding.UTF8.GetBytes(plainText));
            Assert.AreEqual(sha256String, sha256Bytes);
            
            var sha384String = ShaCryptoUtility.ComputeSha384Hash(plainText);
            var sha384Bytes = ShaCryptoUtility.ComputeSha384Hash(Encoding.UTF8.GetBytes(plainText));
            Assert.AreEqual(sha384String, sha384Bytes);
            
            var sha512String = ShaCryptoUtility.ComputeSha512Hash(plainText);
            var sha512Bytes = ShaCryptoUtility.ComputeSha512Hash(Encoding.UTF8.GetBytes(plainText));
            Assert.AreEqual(sha512String, sha512Bytes);
        }

        [Test]
        public void DefaultEncoding_IsUtf8_ForAllAlgorithms()
        {
            const string plainText = "你好";
            
            var sha1Default = ShaCryptoUtility.ComputeSha1Hash(plainText);
            var sha1Utf8 = ShaCryptoUtility.ComputeSha1Hash(plainText, Encoding.UTF8);
            Assert.AreEqual(sha1Default, sha1Utf8);
            
            var sha256Default = ShaCryptoUtility.ComputeSha256Hash(plainText);
            var sha256Utf8 = ShaCryptoUtility.ComputeSha256Hash(plainText, Encoding.UTF8);
            Assert.AreEqual(sha256Default, sha256Utf8);
            
            var sha384Default = ShaCryptoUtility.ComputeSha384Hash(plainText);
            var sha384Utf8 = ShaCryptoUtility.ComputeSha384Hash(plainText, Encoding.UTF8);
            Assert.AreEqual(sha384Default, sha384Utf8);
            
            var sha512Default = ShaCryptoUtility.ComputeSha512Hash(plainText);
            var sha512Utf8 = ShaCryptoUtility.ComputeSha512Hash(plainText, Encoding.UTF8);
            Assert.AreEqual(sha512Default, sha512Utf8);
        }

        #endregion
    }
}