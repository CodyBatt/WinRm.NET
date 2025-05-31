namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    internal class NtlmClientChallenge :
        NtlmMessage
    {
        public NtlmClientChallenge()
            : base()
        {
            ChallengeFromClient = new byte[8];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                // The array is now filled with cryptographically strong random bytes.
                rng.GetBytes(new Span<byte>(ChallengeFromClient));
            }
        }

        public NtlmClientChallenge(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public byte RespType { get; private set; } = 0x01;

        public byte HiRespType { get; private set; } = 0x01;

        public byte[] ChallengeFromClient { get; private set; } = Array.Empty<byte>();

        public DateTime Time { get; set; }

        public List<AvPair> AvPairs { get; set; } = new List<AvPair>();

        protected override void Build()
        {
            var bytes = new List<byte>();
            bytes.Add(RespType);
            bytes.Add(HiRespType);
            bytes.AddRange(new byte[6]); // Reserved bytes
            bytes.AddRange(BitConverter.GetBytes(Time.ToFileTimeUtc())); // Time in file time format
            bytes.AddRange(ChallengeFromClient);
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
            Time = DateTime.FromFileTime(timestamp);

            // Offset: 16
            // ChallengeFromClient (8 bytes)
            ChallengeFromClient = new byte[8];
            MessageBuffer.Slice(16, 8).Span.CopyTo(ChallengeFromClient);

            // Offset: 28
            // AvPairList (Variable length)
            AvPairs = AvPairHelper.Parse(MessageBuffer.Slice(28).Span);
        }
    }
}
