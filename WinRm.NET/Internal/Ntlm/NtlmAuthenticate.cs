namespace WinRm.NET.Internal.Ntlm
{
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms - This is NTLM, what choice do we have?

    using System.Text;
    using global::Kerberos.NET.Entities;

    internal sealed class NtlmAuthenticate : NtlmMessage
    {
        public NtlmAuthenticate(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
        }

        public NtlmAuthenticate()
            : base()
        {
        }

        public NtlmNegotiateFlag NegotiationFlags { get; set; }

        public string UserName { get; set; } = string.Empty;

        public string DomainName { get; set; } = string.Empty;

        public string Workstation { get; set; } = string.Empty;

        public ReadOnlyMemory<byte> LmChallengeResponse { get; set; } = new byte[24];

        public ReadOnlyMemory<byte> NtChallengeResponse { get; set; }

        public ReadOnlyMemory<byte> EncryptedRandomSessionKey { get; set; }

        public ReadOnlyMemory<byte> MIC { get; set; }

        public void SetFlags(NtlmNegotiateFlag challengeFlags)
        {
            NegotiationFlags = challengeFlags;
            NegotiationFlags &= ~NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_DOMAIN;
            NegotiationFlags &= ~NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_SERVER;
        }

        protected override void Parse()
        {
            throw new NotImplementedException();
        }

        protected override void Build()
        {
            // Variable length payload data:
            //   - DomainName, UserName, WorksationName, LmChallengeResponse, NtChallengeResponse, EncryptedRandomSessionKey
            var domainNameBytes = Encoding.Unicode.GetBytes(DomainName);
            ushort domainNameLength = (ushort)domainNameBytes.Length;
            int domainNameOffset = 88; // Length of fixed data in the message

            var userNameBytes = Encoding.Unicode.GetBytes(UserName);
            ushort userNameLength = (ushort)userNameBytes.Length;
            int userNameOffset = domainNameOffset + domainNameLength;

            var workstationBytes = Encoding.Unicode.GetBytes(Workstation);
            ushort workstationNameLength = (ushort)workstationBytes.Length;
            int workstationNameOffset = userNameOffset + userNameLength;

            var lmChallengeBytes = LmChallengeResponse;
            ushort lmChallengeLength = (ushort)lmChallengeBytes.Length;
            int lmChallengeOffset = workstationNameOffset + workstationNameLength;

            var ntChallengeBytes = NtChallengeResponse;
            ushort ntChallengeLength = (ushort)ntChallengeBytes.Length;
            int ntChallengeOffset = lmChallengeOffset + lmChallengeLength;

            var encryptedRandomSessionKeyBytes = EncryptedRandomSessionKey;
            ushort encryptedRandomSessionKeyLength = (ushort)encryptedRandomSessionKeyBytes.Length;
            int encryptedRandomSessionKeyOffset = ntChallengeOffset + ntChallengeLength;

            var bytes = new List<byte>();
            // Offset: 0
            // Signature (8 bytes)
            bytes.AddRange(Encoding.ASCII.GetBytes("NTLMSSP\0")); // Signature

            // Offset: 8
            // MessageType (4 bytes)
            bytes.AddRange(BitConverter.GetBytes((int)3)); // Message type (Authenticate)

            // Offset: 12
            // LMChallengeResponse (8 bytes)
            bytes.AddPayloadDataReference(lmChallengeOffset, lmChallengeLength);

            // Offset: 20
            // NTChallengeResponseFields (8 bytes)
            bytes.AddPayloadDataReference(ntChallengeOffset, ntChallengeLength);

            // Offset: 28
            // DomainNameFields (8 bytes)
            bytes.AddPayloadDataReference(domainNameOffset, domainNameLength);

            // Offset: 36
            // UserNameFields (8 bytes)
            bytes.AddPayloadDataReference(userNameOffset, userNameLength);

            // Offset: 44
            // WorkstationNameFields (8 bytes)
            bytes.AddPayloadDataReference(workstationNameOffset, (ushort)workstationNameLength);

            // Offset: 52
            // EncryptedRandomSessionKeyFields (8 bytes)
            bytes.AddPayloadDataReference(encryptedRandomSessionKeyOffset, (ushort)EncryptedRandomSessionKey.Length);

            // Offset: 60
            // NegotiationFlags (4 bytes)
            bytes.AddRange(BitConverter.GetBytes((int)NegotiationFlags));

            // Offset: 64
            // Version (8 bytes)
            bytes.AddRange(new NtlmVersion().GetBytes().Span);

            // Offset: 72
            // Message Integrity Code (MIC) (16 bytes)
            if (MIC.Length == 16)
            {
                bytes.AddRange(MIC.Span);
            }
            else
            {
                bytes.AddRange(new byte[16]);
            }

            // PAYLOAD START
            // DomainName, UserName, WorksationName, LmChallengeResponse, NtChallengeResponse, EncryptedRandomSessionKey
            bytes.AddRange(domainNameBytes);
            bytes.AddRange(userNameBytes);
            bytes.AddRange(workstationBytes);
            bytes.AddRange(lmChallengeBytes.Span);
            bytes.AddRange(ntChallengeBytes.Span);
            bytes.AddRange(EncryptedRandomSessionKey.Span);

            MessageBuffer = bytes.ToArray();
        }
    }
}
