namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Buffers.Binary;
    using System.Security.Cryptography;
    using System.Text;
    using global::Kerberos.NET.Entities;

    internal sealed class NtlmChallenge
        : NtlmMessage
    {
        public NtlmChallenge()
            : base()
        {
        }

        public NtlmChallenge(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public string TargetName { get; set; } = string.Empty;

        public ReadOnlyMemory<byte> ServerChallenge { get; set; }

        public NtlmNegotiateFlag Flags { get; set; }

        public TargetInfo TargetInfo { get; set; } = new TargetInfo();

        public NtlmClientChallenge GetClientChallenge(ReadOnlyMemory<byte>? clientChallengeNonce = null, params AvPair[] additionalPairs)
        {
            var clientChallenge = new NtlmClientChallenge();
            if (clientChallengeNonce != null)
            {
                clientChallenge.ChallengeFromClient = (ReadOnlyMemory<byte>)clientChallengeNonce;
            }

            clientChallenge.FileTime = TargetInfo.Timestamp;
            clientChallenge.AvPairs = TargetInfo.GetAvPairs();
            clientChallenge.AvPairs.AddRange(additionalPairs);

            return clientChallenge;
        }

        protected override void Build()
        {
            throw new NotImplementedException();
        }

        protected override void Parse()
        {
            // Offset: 0
            // Signature (8 bytes)
            if (Encoding.ASCII.GetString(MessageBuffer.Slice(0, 8).Span) != "NTLMSSP\0")
            {
                throw new ArgumentException("Missing signature: NTLMSSP", nameof(MessageBuffer));
            }

            // Offset: 8
            // MessageType (4 bytes)
            if (BitConverter.ToInt32(MessageBuffer.Slice(8).Span) != 2)
            {
                throw new ArgumentException("Invalid message type, expected 2 for challenge", nameof(MessageBuffer));
            }

            // Offset: 12
            // TargetNameInfo (len 2 bytes, maxlen 2 bytes, offset 4 bytes)
            short targetNameLen = BitConverter.ToInt16(MessageBuffer.Slice(12).Span);
            short targetNameLenMax = BitConverter.ToInt16(MessageBuffer.Slice(14).Span);
            int targetNameOffset = BitConverter.ToInt32(MessageBuffer.Slice(16).Span);
            if (targetNameLen > 0 && targetNameOffset > 0)
            {
                TargetName = Encoding.Unicode.GetString(MessageBuffer.Slice(targetNameOffset, targetNameLen).Span);
            }

            // Offset: 20
            // Flags (4 bytes)
            Flags = (NtlmNegotiateFlag)BinaryPrimitives.ReadInt32LittleEndian(MessageBuffer.Slice(20).Span);

            // Offset: 24
            // Challenge (8 bytes)
            ServerChallenge = MessageBuffer.Slice(24, 8).ToArray();

            // Offset: 32
            // Reserved (8 bytes)

            // Offset: 40
            // TargetInfo (len 2 bytes, maxlen 2 bytes, offset 4 bytes)
            short targetInfoLen = BitConverter.ToInt16(MessageBuffer.Slice(40).Span);
            short targetInfoLenMax = BitConverter.ToInt16(MessageBuffer.Slice(42).Span);
            int targetInfoOffset = BitConverter.ToInt32(MessageBuffer.Slice(44).Span);
            if (targetInfoLen > 0 && targetInfoOffset > 0)
            {
                TargetInfo = new TargetInfo(MessageBuffer.Slice(targetInfoOffset, targetInfoLen));
            }
        }
    }
}
