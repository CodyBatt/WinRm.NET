namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Text;

    internal sealed class AvPair
    {
        [SetsRequiredMembers]
        public AvPair(AvPairTypes type, byte[] value)
        {
            this.AvType = type;
            this.Value = value;
        }

        public static AvPair Eol => new AvPair(AvPairTypes.MsvAvEOL, Array.Empty<byte>());

        public static AvPair Flags => new AvPair(AvPairTypes.MsvAvFlags, BitConverter.GetBytes((int)AvFlags.INTEGRITY));

        public static AvPair EmptyChannelBindings => new AvPair(AvPairTypes.MsvAvChannelBindings, new byte[16]);

        public static AvPair EmptyCstn => new AvPair(AvPairTypes.MsvAvTargetName, Encoding.Unicode.GetBytes(string.Empty));

        public ushort Type => (ushort)AvType;

        required public AvPairTypes AvType { get; set; }

        required public byte[] Value { get; set; }

        public byte[] GetBytes()
        {
            var bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes(Type));
            bytes.AddRange(BitConverter.GetBytes((ushort)Value.Length));
            if (Value.Length > 0)
            {
                bytes.AddRange(Value);
            }

            return bytes.ToArray();
        }
    }
}
