namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Text;
    using global::Kerberos.NET.Entities;
    using Microsoft.Extensions.Primitives;

    internal class TargetInfo : NtlmMessage
    {
        public TargetInfo()
            : base()
        {
        }

        public TargetInfo(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public string TargetName => (string?)GetValue(AvPairTypes.MsvAvTargetName) ?? string.Empty;

        public string NetBiosDomainName => (string?)GetValue(AvPairTypes.MsvAvNbDomainName) ?? string.Empty;

        public string NetBiosComputerName => (string?)GetValue(AvPairTypes.MsvAvNbComputerName) ?? string.Empty;

        public string DnsDomainName => (string?)GetValue(AvPairTypes.MsvAvDnsDomainName) ?? string.Empty;

        public string DnsComputerName => (string?)GetValue(AvPairTypes.MsvAvDnsComputerName) ?? string.Empty;

        public string DnsTreeName => (string?)GetValue(AvPairTypes.MsvAvDnsTreeName) ?? string.Empty;

        public DateTime Timestamp => (DateTime?)GetValue(AvPairTypes.MsvAvTimestamp) ?? DateTime.MinValue;

        // Is this the right type of flags? I dont' think so.
        public AvFlags Flags => (AvFlags)GetValue(AvPairTypes.MsvAvFlags)!;

        private List<AvPair> AvPairs { get; set; } = new List<AvPair>();

        public List<AvPair> GetAvPairs()
        {
            return AvPairs;
        }

        protected override void Build()
        {
            var bytes = new List<byte>();
            if (!AvPairs.Any(x => x.AvType == AvPairTypes.MsvAvEOL))
            {
                AvPairs.Add(new AvPair((ushort)AvPairTypes.MsvAvEOL, Array.Empty<byte>()));
            }

            MessageBuffer = AvPairHelper.GetBytes(AvPairs);
        }

        protected override void Parse()
        {
            AvPairs = AvPairHelper.Parse(MessageBuffer.Span);
        }

        private object? GetValue(AvPairTypes type)
        {
            var pair = AvPairs.FirstOrDefault(x => x.AvType == type);
            if (pair == null)
            {
                return null;
            }

            if (pair.Type == 9 || (pair.Type >= 0x0001 && pair.Type <= 0x0005))
            {
                // These are the standard AV pairs, we can decode them
                return Encoding.Unicode.GetString(pair.Value);
            }

            switch (pair.Type)
            {
                case 0x0006: // MsvAvFlags
                    return (AvFlags)BitConverter.ToInt32(pair.Value, 0);
                case 0x0007: // MsvAvTimestamp
                    long timestamp = BitConverter.ToInt64(pair.Value, 0);
                    return DateTime.FromFileTime(timestamp);
                case 0x000A: // MsvAvChannelBindings
                    return pair.Value.ToHexString();
            }

            return null;
        }
    }
}
