namespace WinRm.NET.Internal.Ntlm
{
    #pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms - This is NTLM, what choice do we have?

    using System.Security.Cryptography;
    using System.Text;
    using global::Kerberos.NET.Crypto;
    using global::Kerberos.NET.Entities;

    internal sealed class NtlmAuthenticate : NtlmMessage
    {
        public NtlmAuthenticate(ReadOnlyMemory<byte> bytes)
            : base(bytes)
        {
            RandomSessionKey = new byte[16];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                // The array is now filled with cryptographically strong random bytes.
                rng.GetBytes(new Span<byte>(RandomSessionKey));
            }
        }

        private NtlmAuthenticate()
            : base()
        {
        }

        public ReadOnlyMemory<byte> ResponseKeyNt { get; private set; } = ReadOnlyMemory<byte>.Empty;

        public ReadOnlyMemory<byte> ResponseKeyLm { get; private set; } = ReadOnlyMemory<byte>.Empty;

        public ReadOnlyMemory<byte> NtProofStr { get; private set; } = ReadOnlyMemory<byte>.Empty;

        public NtlmNegotiateFlag NegotiationFlags { get; set; }

        public string UserName { get; set; } = string.Empty;

        public string DomainName { get; set; } = string.Empty;

        public string Workstation { get; set; } = string.Empty;

        public byte[] RandomSessionKey { get; set; } = Array.Empty<byte>();

        public NtlmClientChallenge NtChallengeResponse { get; set; } = new NtlmClientChallenge();

        public static NtlmAuthenticate Create(NtlmChallenge challenge, string user, string domainName, string workstation, string password)
        {
            var userdomain = ExtractUserDomain(user);

            NtlmAuthenticate auth = new NtlmAuthenticate();
            auth.ResponseKeyNt = NTOWFv2(password, user, userdomain);
            auth.ResponseKeyLm = LMOWFv2(password, user, userdomain);

            // Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
            // Time is the timestamp from the challenge
            // ResponseVersion is 1
            // HiResponseVersion is 1
            // ClientChallenge is sent to us from the server in the challenge message
            // ServerName is the whole ServerInfo AvPairs list from the challenge message
            var temp = new byte[8];

            // Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
            // Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
            // Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)), ClientChallenge)

            // If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit SessionBaseKey value.

            return auth;
        }

        /*
         * Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
         */
        internal static ReadOnlyMemory<byte> CalculateMic(
            ReadOnlyMemory<byte> randomSessionKey,
            ReadOnlyMemory<byte> negotiateMessage,
            ReadOnlyMemory<byte> challengeMessage,
            ReadOnlyMemory<byte> authenticateMessage)
        {
            var pal = CryptoPal.Platform;
            var hmacMd5 = pal.HmacMd5(randomSessionKey);
            var bytes = new List<byte>();
            bytes.AddRange(negotiateMessage.Span);
            bytes.AddRange(challengeMessage.Span);
            bytes.AddRange(authenticateMessage.Span);
            return hmacMd5.ComputeHash(bytes.ToArray());
        }

        internal static ReadOnlyMemory<byte> EncryptedRandomSessionKey(ReadOnlyMemory<byte> keyExchageKey, ReadOnlyMemory<byte> randomSessionKey)
        {
            byte[] encryptedRandomSessionKey = new byte[randomSessionKey.Length];
            RC4.Transform(keyExchageKey.Span, randomSessionKey.Span, encryptedRandomSessionKey);
            return encryptedRandomSessionKey;
        }

        internal static ReadOnlyMemory<byte> SessionBaseKey(ReadOnlyMemory<byte> responseKeyNt, ReadOnlyMemory<byte> ntProofStr)
        {
            var pal = CryptoPal.Platform;
            var hmacMd5 = pal.HmacMd5(responseKeyNt);
            return hmacMd5.ComputeHash(ntProofStr);
        }

        /*
         * Specification pseudo-code for NTOWFv1
         *
         *  Define NTOWFv1(Passwd, User, UserDom) as MD4(UNICODE(Passwd))
         *  EndDefine
         */
        internal static ReadOnlyMemory<byte> NTOWFv1(string password)
        {
            var pal = CryptoPal.Platform;
            var md4 = pal.Md4();
            return md4.ComputeHash(Encoding.Unicode.GetBytes(password));
        }

        /*
         * Specification pseudo-code for NTOWFv2
         *
         *  Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(
         *    MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )
         *  EndDefine
         */
        internal static ReadOnlyMemory<byte> NTOWFv2(string password, string user, string userdom)
        {
            var pal = CryptoPal.Platform;
            var md4 = pal.Md4();
            var key = md4.ComputeHash(new ReadOnlySpan<byte>(Encoding.Unicode.GetBytes(password)));
            var hmacMd5 = pal.HmacMd5(key);
            return hmacMd5.ComputeHash(new ReadOnlyMemory<byte>(Encoding.Unicode.GetBytes(user.ToUpperInvariant() + userdom)));
        }

        /*  Specification pseudo-code for LMOWFv2
         *
         *  Define LMOWFv2(Passwd, User, UserDom) as NTOWFv2(Passwd, User, UserDom)
         *  EndDefine
         */
        internal static ReadOnlyMemory<byte> LMOWFv2(string password, string user, string userdom)
        {
            return NTOWFv2(password, user, userdom);
        }

        // Calculate the KeyExchangeKey
        internal static ReadOnlyMemory<byte> KXKEY(NtlmNegotiateFlag negFlags, ReadOnlyMemory<byte> sessionBaseKey /*, byte[] lmChallengeResponse, byte[] serverChallenge*/)
        {
            if (negFlags.HasFlag(NtlmNegotiateFlag.NTLMSSP_REQUEST_NON_NT_SESSION_KEY))
            {
                throw new NotImplementedException("NTLMv1 is not implemented");
            }

            return sessionBaseKey;
        }

        internal static string ExtractUserDomain(string user)
        {
            const string defaultDomain = ".";

            if (string.IsNullOrEmpty(user))
            {
                return defaultDomain;
            }

            var parts = user.Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1)
            {
                return parts[0]; // Return the domain part
            }

            parts = user.Split('@', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1)
            {
                return parts[1]; // Return the domain part after '@'
            }

            return defaultDomain; // No domain part found
        }

        internal static ReadOnlyMemory<byte> NtProofString(ReadOnlyMemory<byte> responseKeyNt, ReadOnlyMemory<byte> clientChallengeBytes, ReadOnlyMemory<byte> serverChallengeBytes)
        {
            var pal = CryptoPal.Platform;
            var hmacMd5 = pal.HmacMd5(responseKeyNt);
            var bytes = new List<byte>();
            bytes.AddRange(serverChallengeBytes.Span);
            bytes.AddRange(clientChallengeBytes.Span);
            return hmacMd5.ComputeHash(bytes.ToArray());
        }

        protected override void Parse()
        {
            throw new NotImplementedException();
        }

        protected override void Build()
        {
            var bytes = new List<byte>();
            // Offset: 0
            // Signature (8 bytes)
            bytes.AddRange(Encoding.ASCII.GetBytes("NTLMSSP\0")); // Signature

            // Offset: 8
            // MessageType (4 bytes)
            bytes.AddRange(BitConverter.GetBytes((int)3)); // Message type (Authenticate)

            // Offset: 12
            // LMChallengeResponse (8 bytes)
            bytes.AddRange(new byte[8]); // LMChallengeResponse - not set, so 8 zero bytes

            // Offset: 20
            // NTChallengeResponseFields (8 bytes)
            var clientChallengeBytes = NtChallengeResponse.GetBytes();
            ushort clientChallengeLength = (ushort)clientChallengeBytes.Length;
            int clientChallengeOffset = 88;
            bytes.AddRange(BitConverter.GetBytes(clientChallengeLength));
            bytes.AddRange(BitConverter.GetBytes(clientChallengeLength));
            bytes.AddRange(BitConverter.GetBytes(clientChallengeOffset));

            // Offset: 28
            // DomainNameFields (8 bytes)
            var domainNameBytes = Encoding.Unicode.GetBytes(DomainName);
            ushort domainNameLength = (ushort)domainNameBytes.Length;
            int domainNameOffset = clientChallengeOffset + clientChallengeLength;
            bytes.AddRange(BitConverter.GetBytes(clientChallengeLength));
            bytes.AddRange(BitConverter.GetBytes(clientChallengeLength));
            bytes.AddRange(BitConverter.GetBytes(clientChallengeOffset));

            // Offset: 36
            // UserNameFields (8 bytes)
            var userNameBytes = Encoding.Unicode.GetBytes(UserName);
            ushort userNameLength = (ushort)userNameBytes.Length;
            int userNameOffset = domainNameOffset + domainNameLength;
            bytes.AddRange(BitConverter.GetBytes(userNameLength));
            bytes.AddRange(BitConverter.GetBytes(userNameLength));
            bytes.AddRange(BitConverter.GetBytes(userNameOffset));

            // Offset: 44
            // WorkstationNameFields (8 bytes)
            var workstationBytes = Encoding.Unicode.GetBytes(Workstation);
            ushort workstationNameLength = (ushort)workstationBytes.Length;
            int workstationNameOffset = userNameOffset + userNameLength;
            bytes.AddRange(BitConverter.GetBytes(workstationNameLength));
            bytes.AddRange(BitConverter.GetBytes(workstationNameLength));
            bytes.AddRange(BitConverter.GetBytes(workstationNameOffset));

            // Offset: 52
            // EncryptedRandomSessionKeyFields (8 bytes)
            // TODO: FIX ME!
            byte[] encryptedRandomSessionKey = new byte[16]; // EncryptedRandomSessionKey() goes here
            ushort encryptedRandomSessionKeyLength = 16;
            int encryptedRandomSessionKeyOffset = workstationNameOffset + workstationNameLength;
            bytes.AddRange(BitConverter.GetBytes(encryptedRandomSessionKeyLength));
            bytes.AddRange(BitConverter.GetBytes(encryptedRandomSessionKeyLength));
            bytes.AddRange(BitConverter.GetBytes(encryptedRandomSessionKeyOffset));

            // Offset: 60
            // NegotiationFlags (4 bytes)
            bytes.AddRange(BitConverter.GetBytes((int)NegotiationFlags));

            // Offset: 64
            // Version (8 bytes)
            bytes.AddRange(new NtlmVersion().GetBytes().Span);

            // Offset: 72
            // Message Integrity Code (MIC) (16 bytes)
            bytes.AddRange(new byte[16]);

            // PAYLOAD START

            // Offset: clientChallengeOffset (88)
            bytes.AddRange(clientChallengeBytes.Span);

            // Offset: domainNameOffset
            bytes.AddRange(domainNameBytes);

            // Offset: userNameOffset
            bytes.AddRange(userNameBytes);

            // Offset: workstationNameOffset
            bytes.AddRange(workstationBytes);

            // Offset: encryptedRandomSessionKeyOffset
            bytes.AddRange(encryptedRandomSessionKey);

            MessageBuffer = bytes.ToArray();
        }
    }
}
