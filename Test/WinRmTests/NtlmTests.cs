namespace WinRmTests
{
    using Kerberos.NET;
    using Kerberos.NET.Entities;
    using WinRm.NET.Internal.Ntlm;

    public class NtlmTests
    {
        // Well-known test vectors for NTLMv2 authentication
        // From [MS-NLMP] 4.2.4.1.3
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/946f54bd-76b5-4b18-ace8-6e8c992d5847

        private readonly ReadOnlyMemory<byte> tvServerChallenge = new ReadOnlyMemory<byte>(new byte[]
        { 
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef 
        });
        private readonly ReadOnlyMemory<byte> tvNtofv2 = new ReadOnlyMemory<byte>(new byte[] 
        { 
            0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f
        });
        private readonly ReadOnlyMemory<byte> tvSessionBaseKey = new ReadOnlyMemory<byte>(new byte[]
        {
            0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3
        });
        private readonly ReadOnlyMemory<byte> tvTemp = new ReadOnlyMemory<byte>(new byte[]
        {
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        });
        private readonly ReadOnlyMemory<byte> tvRandomSessionKey = new ReadOnlyMemory<byte>(new byte[]
        {
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        });
        private readonly ReadOnlyMemory<byte> tvEncryptedRandomSessionKey = new ReadOnlyMemory<byte>(new byte[]
        {
            0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90, 0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9, 0xd0, 0x3e
        });

        [Fact]
        public void NTOWFv2TestVectorWorks()
        {
            var bytes = NtlmAuthenticate.NTOWFv2("Password", "User", "Domain");
            Assert.True(SpansAreEqual(tvNtofv2.Span, bytes.Span));
        }

        [Fact]
        public void SessionBaseKeyTestVectorWorks()
        {
            var responseKeyNt = NtlmAuthenticate.NTOWFv2("Password", "User", "Domain");
            var clientChallenge = new NtlmClientChallenge(tvTemp);
            var b = clientChallenge.GetBytes(forceBuild: true);
            Assert.True(SpansAreEqual(tvTemp.Span, b.Span));

            var ntProofStr = NtlmAuthenticate.NtProofString(responseKeyNt, clientChallenge.GetBytes(), tvServerChallenge);
            var bytes = NtlmAuthenticate.SessionBaseKey(responseKeyNt, ntProofStr);
            Assert.True(SpansAreEqual(tvSessionBaseKey.Span, bytes.Span));
        }

        [Fact]
        public void EncryptedRandomSessionKeyTestVectorWorks()
        {
            var responseKeyNt = NtlmAuthenticate.NTOWFv2("Password", "User", "Domain");
            var clientChallenge = new NtlmClientChallenge(tvTemp);
            var ntProofStr = NtlmAuthenticate.NtProofString(responseKeyNt, clientChallenge.GetBytes(), tvServerChallenge);
            var sessionBaseKey = NtlmAuthenticate.SessionBaseKey(responseKeyNt, ntProofStr);
            NtlmNegotiateFlag flag = 0;
            var keyExchangeKey = NtlmAuthenticate.KXKEY(flag, sessionBaseKey);
            var encryptedRandomSessionKey = NtlmAuthenticate.EncryptedRandomSessionKey(keyExchangeKey, tvRandomSessionKey);
            Assert.True(SpansAreEqual(tvEncryptedRandomSessionKey.Span, encryptedRandomSessionKey.Span));
        }

        [Fact]
        public void CanBuildAndParseNegotiate()
        {
            var msg1 = new NtlmNegotiate();
            msg1.Flags = NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE
                | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM_V1
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                | NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_DOMAIN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56;
            var bytes = msg1.GetBytes();

            var msg2 = new NtlmNegotiate(bytes);

            Assert.Equal(msg1.Flags, msg2.Flags);
        }

        [Fact]
        public void CanBuildAndParseVersion()
        {
            var msg = new NtlmVersion();
            Assert.Equal(10, msg.MajorVersion);
            Assert.Equal(0, msg.MinorVersion);
            Assert.Equal(0x0065, msg.BuildVersion);
            Assert.Equal(15, msg.NtlmRevision);

            var bytes = msg.GetBytes();

            var msg2 = new NtlmVersion(bytes);
            Assert.Equal(msg.MajorVersion, msg2.MajorVersion);
            Assert.Equal(msg.MinorVersion, msg2.MinorVersion);
            Assert.Equal(msg.BuildVersion, msg2.BuildVersion);
            Assert.Equal(msg.NtlmRevision, msg2.NtlmRevision);
        }

        [Fact]
        public void CanBuildNegotiateMessage()
        {
            //See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
            var message = new NtlmNegotiate();
            message.Flags = NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE
                | NtlmNegotiateFlag.NTLM_NEGOTIATE_OEM
                | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_LM_KEY
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM_V1
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56;
            var bytes = message.GetBytes();
            var b64 = Convert.ToBase64String(bytes.Span);
            Assert.Equal("TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==", b64);
        }

        [Fact]
        public void CanParseChallenge()
        {
            // See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
            // Base64 encoded NTLM challenge message
            var base64Challenge = "TlRMTVNTUAACAAAAFAAUADgAAAA1gonip8FcXZczWnwAAAAAAAAAAKQApABMAAAACgB8TwAAAA9EAEEATgBWAE0AQwBMAE8AVQBEAAIAFABEAEEATgBWAE0AQwBMAE8AVQBEAAEAFABPAFAALQBBAEcARQBOAFQALQAyAAQAFgBkAGEAbgAuAHYAbQBjAGwAbwB1AGQAAwAsAG8AcAAtAGEAZwBlAG4AdAAtADIALgBkAGEAbgAuAHYAbQBjAGwAbwB1AGQABQAWAGQAYQBuAC4AdgBtAGMAbABvAHUAZAAHAAgABCSj7tHQ2wEAAAAA";
            var expectedFlags = NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE
                | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM_V1
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                | NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_DOMAIN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56;

            var challenge = new NtlmChallenge(Convert.FromBase64String(base64Challenge));

            Assert.Equal("DANVMCLOUD", challenge.TargetName);
            Assert.Equal(expectedFlags, challenge.Flags);
            Assert.Equal(new byte[] { 0xa7, 0xc1, 0x5c, 0x5d, 0x97, 0x33, 0x5a, 0x7c }, challenge.ChallengeBytes);
            Assert.Equal("DANVMCLOUD", challenge.TargetInfo.NetBiosDomainName);
            Assert.Equal("OP-AGENT-2", challenge.TargetInfo.NetBiosComputerName);
            Assert.Equal("dan.vmcloud", challenge.TargetInfo.DnsDomainName);
            Assert.Equal("op-agent-2.dan.vmcloud", challenge.TargetInfo.DnsComputerName);
            Assert.Equal("dan.vmcloud", challenge.TargetInfo.DnsTreeName);
            Assert.Equal("2025-05-29T13:43:20.7972868-06:00", challenge.TargetInfo.Timestamp.ToString("o"));
        }

        private static bool SpansAreEqual(ReadOnlySpan<byte> s1, ReadOnlySpan<byte> s2)
        {
            if (s1.Length != s2.Length)
            {
                return false;
            }

            for(int i = 0; i < s1.Length; i++)
            {
                if (s1[i] != s2[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}