using System;
using System.Text;

namespace ReSharp.Security.Cryptography.Tests
{
    internal static class HexConverter
    {
        public static byte[] FromHexString(string hex, char separator = '\0')
        {
            if (string.IsNullOrEmpty(hex))
                throw new ArgumentNullException(nameof(hex));
            
            hex = hex.Replace(separator.ToString(), "")
                .Replace("0x", "")
                .Replace("0X", "");

            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string length must be even. ");

            var byteLength = hex.Length / 2;
            var bytes = new byte[byteLength];

            for (var i = 0; i < byteLength; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return bytes;
        }
        
        public static string ToHexString(byte[] bytes, string format = "X2", char separator = '\0')
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            var stringBuilder = new StringBuilder(bytes.Length * (2 + (separator != '\0' ? 1 : 0)));
            for (var i = 0; i < bytes.Length; i++)
            {
                stringBuilder.Append(bytes[i].ToString(format));
                if (separator != '\0' && i < bytes.Length - 1)
                    stringBuilder.Append(separator);
            }

            return stringBuilder.ToString();
        }
    }
}