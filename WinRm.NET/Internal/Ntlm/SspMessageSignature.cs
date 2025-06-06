namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;

    internal class SspMessageSignature :
        NtlmMessage
    {
        public SspMessageSignature()
            : base()
        {
        }

        public SspMessageSignature(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public static int Size { get; } = 16;

        public int Version { get; } = 1;

        public ReadOnlyMemory<byte> CheckSum { get; set; }

        public int SequenceNumber { get; set; }

        protected override void Build()
        {
            var bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes(Version));
            bytes.AddRange(CheckSum.Span);
            bytes.AddRange(BitConverter.GetBytes(SequenceNumber));
            MessageBuffer = bytes.ToArray();
        }

        protected override void Parse()
        {
            // Skip version, it must be 1
            CheckSum = MessageBuffer.Slice(4, 8);
            SequenceNumber = BitConverter.ToInt32(MessageBuffer.Slice(12, 4).Span);
        }
    }
}
