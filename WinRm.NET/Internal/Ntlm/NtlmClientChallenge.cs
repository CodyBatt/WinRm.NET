namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;

    internal class NtlmClientChallenge :
        NtlmMessage
    {
        public NtlmClientChallenge()
            : base()
        {
        }

        public NtlmClientChallenge(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public byte RespType { get; private set; } = 0x01;

        public byte HiRespType { get; private set; } = 0x01;

        public ReadOnlyMemory<byte> ChallengeFromClient { get; set; } = NtlmCrypto.Nonce(8);

        public long FileTime { get; set; } = DateTime.UtcNow.ToFileTimeUtc();

        public List<AvPair> AvPairs { get; set; } = new List<AvPair>();

        public ReadOnlyMemory<byte> GetBytesPadded()
        {
            var bytes = new List<byte>(GetBytes(forceBuild: true).ToArray());
            bytes.AddRange(new byte[4]);
            return bytes.ToArray();
        }

        public ReadOnlyMemory<byte> GetBytesNtChallengeResponse(ReadOnlyMemory<byte> ntProofStr)
        {
            var bytes = new List<byte>();
            bytes.AddRange(ntProofStr.Span);
            bytes.AddRange(GetBytesPadded().Span);
            return bytes.ToArray();
        }

        protected override void Build()
        {
            var bytes = new List<byte>();
            bytes.Add(RespType);
            bytes.Add(HiRespType);
            bytes.AddRange(new byte[6]); // Reserved bytes
            bytes.AddRange(BitConverter.GetBytes(FileTime)); // Time in file time format
            bytes.AddRange(ChallengeFromClient.Span);
            bytes.AddRange(new byte[4]); // Reserved bytes
            var avBytes = AvPairHelper.GetBytes(AvPairs);
            bytes.AddRange(avBytes);
            MessageBuffer = bytes.ToArray();
        }

        protected override void Parse()
        {
            // Offset: 0
            // RespType (1 byte)
            RespType = MessageBuffer.Span[0];

            // Offset: 1
            // HiRespType (1 byte)
            HiRespType = MessageBuffer.Span[1];

            // Offset: 8
            // Timestamp (8 bytes)
            long timestamp = BitConverter.ToInt64(MessageBuffer.Slice(8).Span);
            FileTime = timestamp;

            // Offset: 16
            // ChallengeFromClient (8 bytes)
            var buffer = new byte[8];
            MessageBuffer.Slice(16, 8).Span.CopyTo(buffer);
            ChallengeFromClient = buffer;

            // Offset: 28
            // AvPairList (Variable length)
            AvPairs = AvPairHelper.Parse(MessageBuffer.Slice(28).Span);
        }
    }
}
