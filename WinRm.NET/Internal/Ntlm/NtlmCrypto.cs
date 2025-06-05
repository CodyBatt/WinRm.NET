namespace WinRm.NET.Internal.Ntlm
{
    #pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms - This is NTLM, what choice do we have?

    using System.Security.Cryptography;
    using System.Text;
    using global::Kerberos.NET.Crypto;
    using global::Kerberos.NET.Entities;

    public static class NtlmCrypto
    {
        internal static ReadOnlyMemory<byte> Nonce(int length)
        {
            Memory<byte> buffer = new byte[length];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                // The array is now filled with cryptographically strong random bytes.
                rng.GetBytes(buffer.Span);
            }

            return buffer;
        }

        internal static ReadOnlyMemory<byte> CreateRandomSessionKey()
        {
            return Nonce(16).ToArray();
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

        internal static ReadOnlyMemory<byte> TransformRandomSessionKey(ReadOnlyMemory<byte> keyExchageKey, ReadOnlyMemory<byte> randomSessionKey)
        {
            byte[] encryptedRandomSessionKey = new byte[randomSessionKey.Length];
            RC4.Transform(keyExchageKey.Span, randomSessionKey.Span, encryptedRandomSessionKey);
            return encryptedRandomSessionKey;
        }

        internal static ReadOnlyMemory<byte> SessionBaseKey(ReadOnlyMemory<byte> responseKeyNt, ReadOnlyMemory<byte> ntProofStr)
        {
            return HMAC_MD5(responseKeyNt, ntProofStr);
        }

        internal static ReadOnlyMemory<byte> HMAC_MD5(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var pal = CryptoPal.Platform;
            var hmacMd5 = pal.HmacMd5(key);
            return hmacMd5.ComputeHash(data);
        }

        internal static ReadOnlyMemory<byte> ResponseKeyNt(Credentials credentials)
        {
            return NTOWFv2(user: credentials.User, userdom: credentials.Domain, password: credentials.Password);
        }

        internal static Memory<byte> ComputeKey(ReadOnlyMemory<byte> randomSessionKey, bool client, bool signing)
        {
            var pal = CryptoPal.Platform;
            var data = new List<byte>();
            var from = client ? "client" : "server";
            var to = client ? "server" : "client";
            var type = signing ? "signing" : "sealing";
            var magicConstant = Encoding.ASCII.GetBytes($"session key to {from}-to-{to} {type} key magic constant\0");
            data.AddRange(randomSessionKey.Span);
            data.AddRange(magicConstant);
            return pal.Md5().ComputeHash(data.ToArray()).ToArray();
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
        internal static ReadOnlyMemory<byte> NTOWFv2(string user, string userdom, string password)
        {
            var pal = CryptoPal.Platform;
            var md4 = pal.Md4();
            var key = md4.ComputeHash(new ReadOnlySpan<byte>(Encoding.Unicode.GetBytes(password)));
            var hmacMd5 = pal.HmacMd5(key);
            return hmacMd5.ComputeHash(new ReadOnlyMemory<byte>(Encoding.Unicode.GetBytes(user.ToUpperInvariant() + userdom)));
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

        internal static ReadOnlyMemory<byte> NtProofString(ReadOnlyMemory<byte> responseKeyNt, ReadOnlyMemory<byte> serverChallengeBytes, ReadOnlyMemory<byte> clientChallengeBytes)
        {
            var pal = CryptoPal.Platform;
            var hmacMd5 = pal.HmacMd5(responseKeyNt);
            var bytes = new List<byte>();
            bytes.AddRange(serverChallengeBytes.Span);
            bytes.AddRange(clientChallengeBytes.Span);
            return hmacMd5.ComputeHash(bytes.ToArray());
        }
    }
}
