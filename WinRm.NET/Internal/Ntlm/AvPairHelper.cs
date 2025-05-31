namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Runtime.CompilerServices;
    using System.Text;
    using System.Threading.Tasks;

    internal static class AvPairHelper
    {
        public static List<AvPair> Parse(ReadOnlySpan<byte> avList)
        {
            List<AvPair> pairs = new List<AvPair>();
            int offset = 0;
            while (offset < avList.Length)
            {
                if (avList.Length - offset < 4)
                {
                    throw new ArgumentException("Invalid AV pair length, expected at least 4 bytes for type and length", nameof(avList));
                }

                ushort type = BitConverter.ToUInt16(avList.Slice(offset, 2));
                ushort length = BitConverter.ToUInt16(avList.Slice(offset + 2, 2));
                offset += 4;

                if (avList.Length - offset < length)
                {
                    throw new ArgumentException("Invalid AV pair length, not enough data for value", nameof(avList));
                }

                byte[] value = avList.Slice(offset, length).ToArray();
                pairs.Add(new AvPair(type, value));
                offset += length;
            }

            return pairs;
        }

        public static byte[] GetBytes(this List<AvPair> avList)
        {
            var bytes = new List<byte>();
            foreach (AvPair pair in avList)
            {
                bytes.AddRange(pair.GetBytes());
            }

            return bytes.ToArray();
        }
    }

    internal sealed class AvPair
    {
        [SetsRequiredMembers]
        public AvPair(ushort type, byte[] value)
        {
            this.Type = type;
            this.Value = value;
        }

        public AvPairTypes AvType => (AvPairTypes)Type;

        required public ushort Type { get; init; }

        required public byte[] Value { get; init; }

        public string TypeName => AvType.ToString();

        public string StringValue()
        {
            if (Type == 0x0000)
            {
                return "EOL";
            }
            else if (Type == 0x0009 || (Type >= 0x0001 && Type <= 0x0005))
            {
                return Encoding.Unicode.GetString(Value);
            }
            else if (Type == 0x0006)
            {
                var flags = (AvFlags)BitConverter.ToInt32(Value);
                var sb = new StringBuilder("Flags:");
                foreach (var value in Enum.GetValues<AvFlags>())
                {
                    if (flags.HasFlag(value))
                    {
                        sb.Append($" ({value})");
                    }
                }

                return sb.ToString();
            }
            else if (Type == 0x0007)
            {
                var fileTime = BitConverter.ToInt64(Value);
                return DateTime.FromFileTimeUtc(fileTime).ToString("o"); // ISO 8601 format
            }
            else if (Type == 0x0008)
            {
                return "Single Host Data (not implemented) see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f221c061-cc40-4471-95da-d2ff71c85c5b";
            }
            else if (Type == 0x000A)
            {
                return $"Channel Bindings Hash: {Value.ToHexString()}";
            }

            return $"Unknown Type (0x{BitConverter.GetBytes(Type).ToHexString()})";
        }

        public byte[] GetBytes()
        {
            var bytes = new List<byte>(4 + Value.Length);
            bytes.AddRange(BitConverter.GetBytes(Type));
            bytes.AddRange(BitConverter.GetBytes((ushort)Value.Length));
            bytes.AddRange(Value);
            return bytes.ToArray();
        }
    }
}
