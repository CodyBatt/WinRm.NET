namespace WinRm.NET.Internal.Ntlm
{
    using System.Buffers.Binary;
    using System.Text;
    using global::Kerberos.NET.Entities;

    internal sealed class NtlmNegotiate
        : NtlmMessage
    {
        public NtlmNegotiate()
            : base()
        {
        }

        public NtlmNegotiate(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public NtlmNegotiateFlag Flags { get; set; }

        public NtlmVersion Version { get; set; } = new NtlmVersion();

        protected override void Build()
        {
            List<byte> messageBytes = new List<byte>();
            messageBytes.AddRange(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            messageBytes.AddRange(BitConverter.GetBytes((int)1));
            messageBytes.AddRange(BitConverter.GetBytes((int)Flags));
            messageBytes.AddRange(new byte[8]);
            messageBytes.AddRange(new byte[8]);
            messageBytes.AddRange(Version.GetBytes().Span);
            MessageBuffer = messageBytes.ToArray();
        }

        protected override void Parse()
        {
            Flags = (NtlmNegotiateFlag)BinaryPrimitives.ReadInt32LittleEndian(MessageBuffer.Span.Slice(12));
            Version = new NtlmVersion(MessageBuffer.Slice(32, 8));
        }
    }
}
