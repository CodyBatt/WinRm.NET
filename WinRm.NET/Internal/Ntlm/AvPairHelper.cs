namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
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

                AvPairTypes type = (AvPairTypes)BitConverter.ToUInt16(avList.Slice(offset, 2));
                // Skip EOL when parsing and append it when we serialize
                if (type == 0x00)
                {
                    break;
                }

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
            foreach (AvPair pair in avList.Where(x => x.AvType != AvPairTypes.MsvAvEOL))
            {
                bytes.AddRange(pair.GetBytes());
            }

            bytes.AddRange(AvPair.Eol.GetBytes());
            return bytes.ToArray();
        }

        public static AvPair AddAvFlags(this AvPair pair, AvFlags flags)
        {
            AvFlags flagValue = (AvFlags)BitConverter.ToInt32(pair.Value, 0);
            flagValue |= flags;
            pair.Value = BitConverter.GetBytes((int)flagValue);
            return pair;
        }

        public static AvPair RemoveAvFlags(this AvPair pair, AvFlags flags)
        {
            AvFlags flagValue = (AvFlags)BitConverter.ToInt32(pair.Value, 0);
            flagValue &= ~flags;
            pair.Value = BitConverter.GetBytes((int)flagValue);
            return pair;
        }

        public static string StringValue(this AvPair avPair)
        {
            if (avPair.Type == 0x0000)
            {
                return "EOL";
            }
            else if (avPair.Type == 0x0009 || (avPair.Type >= 0x0001 && avPair.Type <= 0x0005))
            {
                return Encoding.Unicode.GetString(avPair.Value);
            }
            else if (avPair.Type == 0x0006)
            {
                var flags = (AvFlags)BitConverter.ToInt32(avPair.Value);
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
            else if (avPair.Type == 0x0007)
            {
                var fileTime = BitConverter.ToInt64(avPair.Value);
                return DateTime.FromFileTimeUtc(fileTime).ToString("o"); // ISO 8601 format
            }
            else if (avPair.Type == 0x0008)
            {
                return "Single Host Data (not implemented) see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f221c061-cc40-4471-95da-d2ff71c85c5b";
            }
            else if (avPair.Type == 0x000A)
            {
                return $"Channel Bindings Hash: {avPair.Value.ToHexString()}";
            }

            return $"Unknown Type (0x{BitConverter.GetBytes(avPair.Type).ToHexString()})";
        }
    }
}
