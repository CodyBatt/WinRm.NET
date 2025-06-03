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
            messageBytes.AddRange(Encoding.ASCII.GetBytes("NTLMSSP\0")); // Signature
            messageBytes.AddRange(BitConverter.GetBytes((int)1)); // Message type (Negotiate)
            messageBytes.AddRange(BitConverter.GetBytes((int)Flags)); // Flags
            messageBytes.AddRange(new byte[8]); // OEM DOMAIN - not set, so 8 zero bytes
            messageBytes.AddRange(new byte[8]); // OEM WORKSTATION - not set, so 8 zero bytes
            messageBytes.AddRange(Version.GetBytes().Span); // Version
            MessageBuffer = messageBytes.ToArray();
        }

        protected override void Parse()
        {
            Flags = (NtlmNegotiateFlag)BinaryPrimitives.ReadInt32LittleEndian(MessageBuffer.Span.Slice(12));
            Version = new NtlmVersion(MessageBuffer.Slice(32, 8));
        }
    }
}
