namespace WinRm.NET.Internal.Ntlm
{
    using System;

    internal class PayloadData
    {
        public const int Size = 8;

        public PayloadData(ReadOnlyMemory<byte> data, int offset)
        {
            Length = BitConverter.ToUInt16(data.Slice(offset, 2).Span);
            MaxLength = BitConverter.ToUInt16(data.Slice(offset + 2, 2).Span);
            Offset = BitConverter.ToUInt16(data.Slice(offset + 4, 4).Span);
            Data = data.Slice(Offset, Length);
        }

        public ushort Length { get; private set; }

        public ushort MaxLength { get; private set; }

        public int Offset { get; private set; }

        public ReadOnlyMemory<byte> Data { get; set; }
    }
}
