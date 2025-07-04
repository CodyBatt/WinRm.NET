﻿namespace WinRm.NET.Internal.Ntlm
{
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

        public bool RemoteIsDomainJoined { get; private set; }

        public static (ReadOnlyMemory<byte> ChallengeResponse, ReadOnlyMemory<byte> SessionKey)
            CreateAuthenticateMessage(Credentials credentials, ReadOnlyMemory<byte> negotiateBytes, ReadOnlyMemory<byte> challengeBytes)
        {
            // Initialize authenticate message
            NtlmChallenge challenge = new NtlmChallenge(challengeBytes);
            NtlmAuthenticate auth = new NtlmAuthenticate();
            auth.UserName = credentials.User;
            auth.DomainName = credentials.Domain;
            auth.Workstation = System.Environment.MachineName;
            auth.SetFlags(challenge.Flags);

            // Compute the key exchange data
            var randomSessionKey = NtlmCrypto.CreateRandomSessionKey();
            var responseKeyNt = NtlmCrypto.ResponseKeyNt(credentials);
            var clientChallenge = challenge.GetClientChallenge(null, AvPair.Flags, AvPair.EmptyChannelBindings, AvPair.EmptyCstn);
            var ntProofStr = NtlmCrypto.NtProofString(responseKeyNt, challenge.ServerChallenge, clientChallenge.GetBytesPadded());

            auth.NtChallengeResponse = clientChallenge.GetBytesNtChallengeResponse(ntProofStr);
            var sessionBaseKey = NtlmCrypto.SessionBaseKey(responseKeyNt, ntProofStr);
            var kxkey = NtlmCrypto.KXKEY(auth.NegotiationFlags, sessionBaseKey);
            auth.EncryptedRandomSessionKey = NtlmCrypto.RC4KRandomSessionKey(kxkey, randomSessionKey);

            // Set the MIC
            var authenticateBytes = auth.GetBytes();
            auth.MIC = NtlmCrypto.CalculateMic(randomSessionKey, negotiateBytes, challengeBytes, authenticateBytes);

            // Get bytes again after setting MIC
            var challengeResponseBytes = auth.GetBytes(forceBuild: true);

            return (ChallengeResponse: challengeResponseBytes, SessionKey: randomSessionKey);
        }

        public void SetFlags(NtlmNegotiateFlag challengeFlags)
        {
            if (!challengeFlags.HasFlag(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128))
            {
                throw new InvalidOperationException("[PROTOCOL_ERROR] Target system does not support 128-bit encryption.");
            }

            RemoteIsDomainJoined = challengeFlags.HasFlag(NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_DOMAIN);

            NegotiationFlags = challengeFlags;

            // clear the target flags. These are just used for the remote host to indicate
            // whether it is domain joined. We should not send these in the authenticate response.
            NegotiationFlags &= ~NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_DOMAIN;
            NegotiationFlags &= ~NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_SERVER;
        }

        protected override void Parse()
        {
            var offset = 0;
            var signature = Encoding.ASCII.GetString(MessageBuffer.Slice(offset, 8).Span);
            offset += 8;

            var messageType = BitConverter.ToInt32(MessageBuffer.Slice(offset, 4).Span);
            offset += 4;

            var lmChallengeResponse = new PayloadData(MessageBuffer, offset);
            offset += PayloadData.Size;

            var ntChallengeResponse = new PayloadData(MessageBuffer, offset);
            offset += PayloadData.Size;

            var domainName = new PayloadData(MessageBuffer, offset);
            offset += PayloadData.Size;

            var userName = new PayloadData(MessageBuffer, offset);
            offset += PayloadData.Size;

            var workstation = new PayloadData(MessageBuffer, offset);
            offset += PayloadData.Size;

            var encryptedSessionKey = new PayloadData(MessageBuffer, offset);
            offset += PayloadData.Size;

            NegotiationFlags = (NtlmNegotiateFlag)BitConverter.ToInt32(MessageBuffer.Slice(offset, 4).Span);
            offset += 4;

            var version = new NtlmVersion(MessageBuffer.Slice(offset, 8));
            offset += 8;

            MIC = MessageBuffer.Slice(offset, 16).ToArray();
            LmChallengeResponse = lmChallengeResponse.Data;
            NtChallengeResponse = ntChallengeResponse.Data;
            EncryptedRandomSessionKey = encryptedSessionKey.Data;
            DomainName = Encoding.Unicode.GetString(domainName.Data.Span);
            UserName = Encoding.Unicode.GetString(userName.Data.Span);
            Workstation = Encoding.Unicode.GetString(workstation.Data.Span);
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
