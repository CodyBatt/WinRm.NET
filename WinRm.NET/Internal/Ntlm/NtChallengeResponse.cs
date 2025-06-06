namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;

    internal class NtChallengeResponse
        : NtlmMessage
    {
        public NtChallengeResponse()
            : base()
        {
        }

        public NtChallengeResponse(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public ReadOnlyMemory<byte> NtProofStr { get; set; }

        public NtlmClientChallenge ClientChallenge { get; set; } = new NtlmClientChallenge();

        protected override void Build()
        {
            var bytes = new List<byte>();
            bytes.AddRange(NtProofStr.Span);
            bytes.AddRange(ClientChallenge.GetBytesPadded().Span);
            MessageBuffer = bytes.ToArray();
        }

        protected override void Parse()
        {
            NtProofStr = MessageBuffer.Slice(0, 16);
            ClientChallenge = new NtlmClientChallenge(MessageBuffer.Slice(16, MessageBuffer.Length - 20));
        }
    }
}
