using System;
using NUnit.Framework;

namespace ReSharp.Security.Cryptography.Tests
{
    [TestFixture]
    public class CryptoUtilityTests
    {
        [Test]
        public void GenerateRandomKey_DefaultLength_ReturnsValidByteArray()
        {
            var key = CryptoUtility.GenerateRandomKey();
            
            Assert.IsNotNull(key);
            Assert.AreEqual(16, key.Length);
        }

        [Test]
        public void GenerateRandomKey_CustomLength_ReturnsValidByteArray()
        {
            const int length = 32;
            
            var key = CryptoUtility.GenerateRandomKey(length);
            
            Assert.IsNotNull(key);
            Assert.AreEqual(length, key.Length);
        }

        [Test]
        public void GenerateRandomKey_ZeroLength_ThrowsArgumentOutOfRangeException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoUtility.GenerateRandomKey(0));
        }

        [Test]
        public void GenerateRandomKey_NegativeLength_ThrowsArgumentOutOfRangeException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoUtility.GenerateRandomKey(-1));
        }

        [Test]
        public void GenerateRandomKey_LargeLength_ReturnsValidByteArray()
        {
            const int length = 256;
            
            var key = CryptoUtility.GenerateRandomKey(length);
            
            Assert.IsNotNull(key);
            Assert.AreEqual(length, key.Length);
        }

        [Test]
        public void GenerateRandomKey_MultipleCalls_ReturnsDifferentKeys()
        {
            var key1 = CryptoUtility.GenerateRandomKey();
            var key2 = CryptoUtility.GenerateRandomKey();
            
            Assert.AreNotEqual(key1, key2);
        }

        [Test]
        public void GenerateRandomKeyString_DefaultParameters_ReturnsValidString()
        {
            var keyString = CryptoUtility.GenerateRandomKeyString();
            
            Assert.IsNotNull(keyString);
            Assert.AreEqual(16, keyString.Length);
        }

        [Test]
        public void GenerateRandomKeyString_CustomLength_ReturnsValidString()
        {
            const int length = 32;
            
            var keyString = CryptoUtility.GenerateRandomKeyString(length);
            
            Assert.IsNotNull(keyString);
            Assert.AreEqual(length, keyString.Length);
        }

        [Test]
        public void GenerateRandomKeyString_ZeroLength_ThrowsArgumentOutOfRangeException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoUtility.GenerateRandomKeyString(0));
        }

        [Test]
        public void GenerateRandomKeyString_NegativeLength_ThrowsArgumentOutOfRangeException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoUtility.GenerateRandomKeyString(-5));
        }

        [Test]
        public void GenerateRandomKeyString_OnlyLowercaseCharacters_ReturnsValidString()
        {
            var keyString = CryptoUtility.GenerateRandomKeyString(20, 
                includeLowercaseCharacters: true,
                includeUppercaseCharacters: false,
                includeNumbers: false,
                includeSpecialCharacters: false);
            
            Assert.IsNotNull(keyString);
            Assert.AreEqual(20, keyString.Length);
            foreach (var c in keyString)
            {
                Assert.IsTrue(c >= 'a' && c <= 'z');
            }
        }

        [Test]
        public void GenerateRandomKeyString_OnlyUppercaseCharacters_ReturnsValidString()
        {
            var keyString = CryptoUtility.GenerateRandomKeyString(20,
                includeLowercaseCharacters: false,
                includeUppercaseCharacters: true,
                includeNumbers: false,
                includeSpecialCharacters: false);
            
            Assert.IsNotNull(keyString);
            Assert.AreEqual(20, keyString.Length);
            foreach (var c in keyString)
            {
                Assert.IsTrue(c >= 'A' && c <= 'Z');
            }
        }

        [Test]
        public void GenerateRandomKeyString_OnlyNumbers_ReturnsValidString()
        {
            var keyString = CryptoUtility.GenerateRandomKeyString(20,
                includeLowercaseCharacters: false,
                includeUppercaseCharacters: false,
                includeNumbers: true,
                includeSpecialCharacters: false);
            
            Assert.IsNotNull(keyString);
            Assert.AreEqual(20, keyString.Length);
            foreach (var c in keyString)
            {
                Assert.IsTrue(c >= '0' && c <= '9');
            }
        }

        [Test]
        public void GenerateRandomKeyString_AllCharacterTypes_ReturnsValidString()
        {
            var keyString = CryptoUtility.GenerateRandomKeyString(100,
                includeLowercaseCharacters: true,
                includeUppercaseCharacters: true,
                includeNumbers: true,
                includeSpecialCharacters: true);
            
            Assert.IsNotNull(keyString);
            Assert.AreEqual(100, keyString.Length);
        }

        [Test]
        public void GenerateRandomKeyString_NoCharacterTypes_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => CryptoUtility.GenerateRandomKeyString(10,
                    includeLowercaseCharacters: false,
                    includeUppercaseCharacters: false,
                    includeNumbers: false,
                    includeSpecialCharacters: false));
        }

        [Test]
        public void GenerateRandomKeyString_MultipleCalls_ReturnsDifferentStrings()
        {
            var keyString1 = CryptoUtility.GenerateRandomKeyString();
            var keyString2 = CryptoUtility.GenerateRandomKeyString();
            
            Assert.AreNotEqual(keyString1, keyString2);
        }

        [Test]
        public void GenerateRandomKeyString_LargeLength_ReturnsValidString()
        {
            const int length = 1000;
            
            var keyString = CryptoUtility.GenerateRandomKeyString(length);
            
            Assert.IsNotNull(keyString);
            Assert.AreEqual(length, keyString.Length);
        }

        [Test]
        public void GenerateRandomKeyString_VerifyRandomDistribution_HasReasonableDistribution()
        {
            var keyString = CryptoUtility.GenerateRandomKeyString(1000);
            
            var hasLowercase = false;
            var hasUppercase = false;
            var hasNumber = false;
            var hasSpecial = false;
            
            foreach (var c in keyString)
            {
                if (c >= 'a' && c <= 'z') hasLowercase = true;
                else if (c >= 'A' && c <= 'Z') hasUppercase = true;
                else if (c >= '0' && c <= '9') hasNumber = true;
                else hasSpecial = true;
            }
            
            Assert.IsTrue(hasLowercase, "Should contain lowercase characters");
            Assert.IsTrue(hasUppercase, "Should contain uppercase characters");
            Assert.IsTrue(hasNumber, "Should contain numbers");
            Assert.IsTrue(hasSpecial, "Should contain special characters");
        }
    }
}
