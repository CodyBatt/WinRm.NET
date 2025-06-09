namespace WinRmTests
{
    using Kerberos.NET.Entities;
    using System.Text;
    using WinRm.NET.Internal;
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
        private readonly string NtProofHex = "68cd0ab851e51c96aabc927bebef6a1c";

        private readonly Credentials StandardCredentials = new Credentials("User", "Domain", "Password");

        [Fact]
        public void NTOWFv2TestVectorWorks()
        {
            var b2 = NtlmCrypto.NTOWFv2("User", "Domain", "Password");
            Assert.True(Test.SpansAreEqual(tvNtofv2.Span, b2.Span));
        }

        [Fact]
        public void SessionBaseKeyTestVectorWorks()
        {
            var responseKeyNt = NtlmCrypto.ResponseKeyNt(StandardCredentials);
            var clientChallenge = new NtlmClientChallenge(tvTemp);
            var b = clientChallenge.GetBytes(forceBuild: true);
            // The test vector for temp is clientChallenge with padded bytes
            Assert.False(Test.SpansAreEqual(tvTemp.Span, b.Span));

            var bPadded = clientChallenge.GetBytesPadded();
            Assert.True(Test.SpansAreEqual(tvTemp.Span, bPadded.Span));

            var ntProofStr = NtlmCrypto.NtProofString(responseKeyNt, tvServerChallenge, clientChallenge.GetBytesPadded());
            Assert.Equal(NtProofHex, ntProofStr.Span.ToHexString());

            var bytes = NtlmCrypto.SessionBaseKey(responseKeyNt, ntProofStr);
            Assert.True(Test.SpansAreEqual(tvSessionBaseKey.Span, bytes.Span));
        }

        [Fact]
        public void EncryptedRandomSessionKeyTestVectorWorks()
        {
            var responseKeyNt = NtlmCrypto.ResponseKeyNt(StandardCredentials);
            var clientChallenge = new NtlmClientChallenge(tvTemp);
            var ntProofStr = NtlmCrypto.NtProofString(responseKeyNt, serverChallengeBytes: tvServerChallenge, clientChallengeBytes: clientChallenge.GetBytesPadded());
            Assert.Equal(NtProofHex, ntProofStr.Span.ToHexString());

            var sessionBaseKey = NtlmCrypto.SessionBaseKey(responseKeyNt, ntProofStr);
            NtlmNegotiateFlag flag = 0;
            var keyExchangeKey = NtlmCrypto.KXKEY(flag, sessionBaseKey);
            var encryptedRandomSessionKey = NtlmCrypto.RC4KRandomSessionKey(keyExchangeKey, tvRandomSessionKey);
            Assert.True(Test.SpansAreEqual(tvEncryptedRandomSessionKey.Span, encryptedRandomSessionKey.Span));
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
            Assert.Equal(26100, msg.BuildVersion);
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
            Assert.True(Test.SpansAreEqual(new byte[] { 0xa7, 0xc1, 0x5c, 0x5d, 0x97, 0x33, 0x5a, 0x7c }, challenge.ServerChallenge.Span));
            Assert.Equal("DANVMCLOUD", challenge.TargetInfo.NetBiosDomainName);
            Assert.Equal("OP-AGENT-2", challenge.TargetInfo.NetBiosComputerName);
            Assert.Equal("dan.vmcloud", challenge.TargetInfo.DnsDomainName);
            Assert.Equal("op-agent-2.dan.vmcloud", challenge.TargetInfo.DnsComputerName);
            Assert.Equal("dan.vmcloud", challenge.TargetInfo.DnsTreeName);
            var dateTime = DateTime.FromFileTime(challenge.TargetInfo.Timestamp).ToUniversalTime();
            var dateTimeStr = dateTime.ToString("o");
            Assert.Equal("2025-05-29T19:43:20.7972868Z", dateTimeStr);
        }

        [Fact]
        public void EncryptDataTest()
        {
            var encryptor = new NtlmEncryptor(tvRandomSessionKey);
            var plaintextBytes = Encoding.Unicode.GetBytes("Plaintext");
            var expectedSealKey = new byte[] { 0x59, 0xf6, 0x00, 0x97, 0x3c, 0xc4, 0x96, 0x0a, 0x25, 0x48, 0x0a, 0x7c, 0x19, 0x6e, 0x4c, 0x58 };
            var expectedSignKey = new byte[] { 0x47, 0x88, 0xdc, 0x86, 0x1b, 0x47, 0x82, 0xf3, 0x5d, 0x43, 0xfd, 0x98, 0xfe, 0x1a, 0x2d, 0x39 };
            Assert.True(Test.SpansAreEqual(expectedSealKey, encryptor.ClientSealingKey.Span));
            Assert.True(Test.SpansAreEqual(expectedSignKey, encryptor.ClientSigningKey.Span));
            var expectedEncryptedData = new byte[] { 0x54, 0xe5, 0x01, 0x65, 0xbf, 0x19, 0x36, 0xdc, 0x99, 0x60, 0x20, 0xc1, 0x81, 0x1b, 0x0f, 0x06, 0xfb, 0x5f };
            var data = encryptor.Client.Transform(plaintextBytes);
            Assert.True(Test.SpansAreEqual(expectedEncryptedData, data.Span));
            var expectedChecksum = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x7f, 0xb3, 0x8e, 0xc5, 0xc5, 0x5d, 0x49, 0x76, 0x00, 0x00, 0x00, 0x00 };
            var checksum = encryptor.Client.ComputeSignature(0, plaintextBytes);
            Assert.True(Test.SpansAreEqual(expectedChecksum, checksum.Span));
        }
    }
}