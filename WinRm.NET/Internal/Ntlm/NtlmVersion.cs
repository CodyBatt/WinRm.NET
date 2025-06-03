namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal class NtlmVersion
        : NtlmMessage
    {
        public NtlmVersion()
            : base()
        {
        }

        public NtlmVersion(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public byte MajorVersion { get; set; } = 10;

        public byte MinorVersion { get; set; }

        public short BuildVersion { get; set; } = 26100;

        public byte NtlmRevision { get; set; } = 15;

        protected override void Build()
        {
            var bytes = new List<byte>();
            bytes.Add((byte)MajorVersion);
            bytes.Add((byte)MinorVersion);
            bytes.AddRange(BitConverter.GetBytes((short)BuildVersion));
            bytes.AddRange(new byte[3]);
            bytes.Add((byte)NtlmRevision);
            MessageBuffer = bytes.ToArray();
        }

        protected override void Parse()
        {
            MajorVersion = MessageBuffer.Span[0];
            MinorVersion = MessageBuffer.Span[1];
            BuildVersion = BitConverter.ToInt16(MessageBuffer.Span.Slice(2, 2));
            NtlmRevision = MessageBuffer.Span[7];
        }
    }
}
