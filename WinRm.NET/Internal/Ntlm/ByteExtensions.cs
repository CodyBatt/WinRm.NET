namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal static class ByteExtensions
    {
        public static string ToBase64(this ReadOnlySpan<byte> bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }

            return Convert.ToBase64String(bytes);
        }

        public static string ToBase64(this byte[] bytes)
        {
            return new ReadOnlySpan<byte>(bytes).ToBase64();
        }

        public static byte[] FromBase64(this string base64String)
        {
            if (string.IsNullOrEmpty(base64String))
            {
                return Array.Empty<byte>();
            }

            return Convert.FromBase64String(base64String);
        }

        public static string ToUtf8String(this ReadOnlySpan<byte> bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }

            return Encoding.UTF8.GetString(bytes);
        }

        public static string ToUtf8String(this byte[] bytes)
        {
            return new ReadOnlySpan<byte>(bytes).ToUtf8String();
        }

        public static byte[] ToUtf8Bytes(this string str)
        {
            if (string.IsNullOrEmpty(str))
            {
                return Array.Empty<byte>();
            }

            return Encoding.UTF8.GetBytes(str);
        }

        public static string ToHexString(this ReadOnlySpan<byte> bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }

            return System.Convert.ToHexString(bytes).ToLowerInvariant();
        }

        public static string ToHexString(this byte[] bytes)
        {
            return new ReadOnlySpan<byte>(bytes).ToHexString();
        }
    }
}
