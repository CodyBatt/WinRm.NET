namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;

    internal class SspMessageHeader
        : NtlmMessage
    {
        public SspMessageHeader()
            : base()
        {
        }

        public SspMessageHeader(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public int Length { get; private set; } = SspMessageSignature.Size;

        public SspMessageSignature Signature { get; set; } = new SspMessageSignature();

        public int SequenceNumber { get; set; }

        protected override void Build()
        {
            var bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes(Length));
            bytes.AddRange(Signature.GetBytes().Span);
            MessageBuffer = bytes.ToArray();
        }

        protected override void Parse()
        {
            // Skip version, it must be 1
            Length = BitConverter.ToInt32(MessageBuffer.Slice(0, 4).Span);
            Signature = new SspMessageSignature(MessageBuffer.Slice(4));
        }
    }
}
