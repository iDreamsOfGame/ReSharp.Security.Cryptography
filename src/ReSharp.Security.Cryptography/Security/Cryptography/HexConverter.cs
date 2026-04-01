using System;

namespace ReSharp.Security.Cryptography
{
    internal static class HexConverter
    {
        public static byte[] FromHexString(string hexString, char separator = '\0')
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentNullException(nameof(hexString));
            
            hexString = hexString.Replace(separator.ToString(), "")
                .Replace("0x", "")
                .Replace("0X", "");

            if (hexString.Length % 2 != 0)
                throw new ArgumentException("Hex string length must be even. ");

            var byteLength = hexString.Length / 2;
            var bytes = new byte[byteLength];

            for (var i = 0; i < byteLength; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return bytes;
        }
        
        public static string ToHexString(byte[]? data, bool toUppercase = true)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            var hexString = BitConverter.ToString(data).Replace("-", string.Empty);
            return toUppercase ? hexString : hexString.ToLower();
        }
    }
}