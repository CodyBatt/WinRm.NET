namespace WinRmTests
{
    using Kerberos.NET;
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

        private readonly Credentials StandardCredentials = new Credentials("User", "Password")
        {
            Domain = "Domain"
        };

        [Fact]
        public void NTOWFv2TestVectorWorks()
        {
            var bytes = NtlmCrypto.NTOWFv2("User", "Domain", "Password");
            Assert.True(SpansAreEqual(tvNtofv2.Span, bytes.Span));
        }

        [Fact]
        public void SessionBaseKeyTestVectorWorks()
        {
            var responseKeyNt = NtlmCrypto.ResponseKeyNt(StandardCredentials);
            var clientChallenge = new NtlmClientChallenge(tvTemp);
            var b = clientChallenge.GetBytes(forceBuild: true);
            // The test vector for temp is clientChallenge with padded bytes
            Assert.False(SpansAreEqual(tvTemp.Span, b.Span));

            var bPadded = clientChallenge.GetBytesPadded();
            Assert.True(SpansAreEqual(tvTemp.Span, bPadded.Span));

            var ntProofStr = NtlmCrypto.NtProofString(responseKeyNt, tvServerChallenge, clientChallenge.GetBytesPadded());
            Assert.Equal(NtProofHex, ntProofStr.Span.ToHexString());

            var bytes = NtlmCrypto.SessionBaseKey(responseKeyNt, ntProofStr);
            Assert.True(SpansAreEqual(tvSessionBaseKey.Span, bytes.Span));
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
            var encryptedRandomSessionKey = NtlmCrypto.TransformRandomSessionKey(keyExchangeKey, tvRandomSessionKey);
            Assert.True(SpansAreEqual(tvEncryptedRandomSessionKey.Span, encryptedRandomSessionKey.Span));
        }

        [Fact]
        // This is based on a packet capture on some test machines to ensure that
        // we are able to build, parse and compute a real-world NTLMv2 authentication message
        public void SimulateNegotiation()
        {
            // Gotta have the password for this test to work
            var credentials = new Credentials("cbatt-adm@DAN.VMCLOUD", "root4EDMZ");

            // Make sure we can parse and generate the negotiate message
            var b64Negotiate = "TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==";
            var negotiate = new NtlmNegotiate(Convert.FromBase64String(b64Negotiate));
            Assert.Equal(b64Negotiate, negotiate.GetBytes().Span.ToBase64());

            // Make sure we can parse and generate the challenge message
            var b64Challenge = "TlRMTVNTUAACAAAAFAAUADgAAAA1gonil+dqePIrdg0AAAAAAAAAAKQApABMAAAACgB8TwAAAA9EAEEATgBWAE0AQwBMAE8AVQBEAAIAFABEAEEATgBWAE0AQwBMAE8AVQBEAAEAFABPAFAALQBBAEcARQBOAFQALQAyAAQAFgBkAGEAbgAuAHYAbQBjAGwAbwB1AGQAAwAsAG8AcAAtAGEAZwBlAG4AdAAtADIALgBkAGEAbgAuAHYAbQBjAGwAbwB1AGQABQAWAGQAYQBuAC4AdgBtAGMAbABvAHUAZAAHAAgAfsYb+xHQ2wEAAAAA";
            var challenge = new NtlmChallenge(Convert.FromBase64String(b64Challenge));
            Assert.Equal(b64Challenge, challenge.GetBytes().Span.ToBase64());

            // Build the authenticate message using the actual values from the
            // captured session
            NtlmAuthenticate auth = new NtlmAuthenticate();
            auth.UserName = credentials.User;
            auth.DomainName = string.Empty;
            auth.Workstation = "CODY-P2";
            auth.SetFlags(challenge.Flags);

            // Set values from the captured session
            var clientChallengeBytes = new byte[] { 0x99, 0x82, 0xde, 0x95, 0x6c, 0x8a, 0x67, 0x56 };
            var spn = "HOST/10.3.63.237";
            var singleHostData = new byte[] {0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x45, 0xac, 0x2a, 0xeb, 0x41, 0x2f, 0x86, 0x9e, 0x5d, 0x1a, 0x50, 0xbe, 0x79, 0xc1, 0xcf, 0xb3, 0x2b, 0x16, 0x1b, 0x2a, 0xf3, 0xce, 0x66, 0xd5, 0x6a, 0x6d, 0x6, 0xdc, 0x5b, 0xa3, 0x82, 0x3c };
            var singleHost = new AvPair(AvPairTypes.MsvAvSingleHost, singleHostData);
            var channelBindings = new AvPair(AvPairTypes.MsvAvChannelBindings, new byte[16]);
            var spnPair = new AvPair(AvPairTypes.MsvAvTargetName, Encoding.Unicode.GetBytes(spn));
            var timestamp = BitConverter.ToInt64(new byte[] { 0x7e, 0xc6, 0x1b, 0xfb, 0x11, 0xd0, 0xdb, 0x01 });

            // Make sure we can correctly build the client challenge
            var challengeHex = "01010000000000007ec61bfb11d0db019982de956c8a67560000000002001400440041004e0056004d0043004c004f0055004400010014004f0050002d004100470045004e0054002d00320004001600640061006e002e0076006d0063006c006f007500640003002c006f0070002d006100670065006e0074002d0032002e00640061006e002e0076006d0063006c006f007500640005001600640061006e002e0076006d0063006c006f0075006400070008007ec61bfb11d0db010600040002000000080030003000000000000000010000000020000045ac2aeb412f869e5d1a50be79c1cfb32b161b2af3ce66d56a6d06dc5ba3823c0a001000000000000000000000000000000000000900200048004f00530054002f00310030002e0033002e00360033002e003200330037000000000000000000";
            var clientChallenge = challenge.GetClientChallenge(clientChallengeBytes, AvPair.Flags, singleHost, channelBindings, spnPair);
            var clientChallengePaddedBytes = clientChallenge.GetBytesPadded();
            var ntChallengeComputedHex = clientChallengePaddedBytes.Span.ToHexString();
            Assert.Equal(challengeHex, ntChallengeComputedHex);

            // We are computing the crypto keys next
            // Generate a temporary key based on the password
            var responseKeyNt = NtlmCrypto.ResponseKeyNt(credentials);

            // Ensure we have the expected input values
            var expectedServerChallenge = Convert.FromHexString("97e76a78f22b760d");
            Assert.True(SpansAreEqual(expectedServerChallenge, challenge.ServerChallenge.Span));

            // Combine server challenge and client challenge to compute the NT proof string
            var expectedNtProofHex = "a44a9fbcff24f5fd4ec21fa5cf0c8842";
            var ntProofStr = NtlmCrypto.NtProofString(responseKeyNt, challenge.ServerChallenge, clientChallengePaddedBytes);
            Assert.Equal(expectedNtProofHex, ntProofStr.Span.ToHexString());

            // Set the challenge response in the auth message
            auth.NtChallengeResponse = clientChallenge.GetBytesNtChallengeResponse(ntProofStr);

            var sessionBaseKey = NtlmCrypto.SessionBaseKey(responseKeyNt, ntProofStr);
            var kxkey = NtlmCrypto.KXKEY(auth.NegotiationFlags, sessionBaseKey);
            var expectedEncryptedRandomSessionKeyHex = "eb46ee01d11f7119ca5fb9e6b8377ae8";

            // Extracted the known value for this test
            var expectedRandomSessionKeyHex = "8489342b319cc0f2ca0c27b18fb19c62";
            var randomSessionKey = Convert.FromHexString(expectedRandomSessionKeyHex);

            // The session key is encrypted with RC4 symmetric encryption, so we can use the known value for the
            // random session key to get the encrypted value and vice-versa
            auth.EncryptedRandomSessionKey = NtlmCrypto.TransformRandomSessionKey(kxkey, randomSessionKey);
            Assert.Equal(expectedEncryptedRandomSessionKeyHex, auth.EncryptedRandomSessionKey.Span.ToHexString());

            //// Set the MIC
            var negotiateBytes = negotiate.GetBytes();
            var challengeBytes = challenge.GetBytes();
            var authenticateBytes = auth.GetBytes();

            // Make sure that the authenticate message bytes match the expected value with
            // the MIC bytes all set to zero
            var b64AuthenticateBytesMicZero = "TlRMTVNTUAADAAAAGAAYAJAAAABIAUgBqAAAAAAAAABYAAAAKgAqAFgAAAAOAA4AggAAABAAEADwAQAANYKI4goA9GUAAAAPAAAAAAAAAAAAAAAAAAAAAGMAYgBhAHQAdAAtAGEAZABtAEAARABBAE4ALgBWAE0AQwBMAE8AVQBEAEMATwBEAFkALQBQADIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApEqfvP8k9f1Owh+lzwyIQgEBAAAAAAAAfsYb+xHQ2wGZgt6VbIpnVgAAAAACABQARABBAE4AVgBNAEMATABPAFUARAABABQATwBQAC0AQQBHAEUATgBUAC0AMgAEABYAZABhAG4ALgB2AG0AYwBsAG8AdQBkAAMALABvAHAALQBhAGcAZQBuAHQALQAyAC4AZABhAG4ALgB2AG0AYwBsAG8AdQBkAAUAFgBkAGEAbgAuAHYAbQBjAGwAbwB1AGQABwAIAH7GG/sR0NsBBgAEAAIAAAAIADAAMAAAAAAAAAABAAAAACAAAEWsKutBL4aeXRpQvnnBz7MrFhsq885m1WptBtxbo4I8CgAQAAAAAAAAAAAAAAAAAAAAAAAJACAASABPAFMAVAAvADEAMAAuADMALgA2ADMALgAyADMANwAAAAAAAAAAAOtG7gHRH3EZyl+55rg3eug=";
            Assert.Equal(b64AuthenticateBytesMicZero, authenticateBytes.Span.ToBase64());

            // Make sure the calculated MIC matches
            var expectedMicHex = "19538b7e0acdb95e06f9b8f9967b4331";
            auth.MIC = NtlmCrypto.CalculateMic(randomSessionKey, negotiateBytes, challengeBytes, authenticateBytes);
            Assert.Equal(expectedMicHex, auth.MIC.Span.ToHexString());

            // Get FINAL authenticate message bytes again after setting MIC
            var challengeResponseBytes = auth.GetBytes(forceBuild: true);
            var b64challengeResponseBytes = Convert.ToBase64String(challengeResponseBytes.Span);
            var b64Authenticate = "TlRMTVNTUAADAAAAGAAYAJAAAABIAUgBqAAAAAAAAABYAAAAKgAqAFgAAAAOAA4AggAAABAAEADwAQAANYKI4goA9GUAAAAPGVOLfgrNuV4G+bj5lntDMWMAYgBhAHQAdAAtAGEAZABtAEAARABBAE4ALgBWAE0AQwBMAE8AVQBEAEMATwBEAFkALQBQADIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApEqfvP8k9f1Owh+lzwyIQgEBAAAAAAAAfsYb+xHQ2wGZgt6VbIpnVgAAAAACABQARABBAE4AVgBNAEMATABPAFUARAABABQATwBQAC0AQQBHAEUATgBUAC0AMgAEABYAZABhAG4ALgB2AG0AYwBsAG8AdQBkAAMALABvAHAALQBhAGcAZQBuAHQALQAyAC4AZABhAG4ALgB2AG0AYwBsAG8AdQBkAAUAFgBkAGEAbgAuAHYAbQBjAGwAbwB1AGQABwAIAH7GG/sR0NsBBgAEAAIAAAAIADAAMAAAAAAAAAABAAAAACAAAEWsKutBL4aeXRpQvnnBz7MrFhsq885m1WptBtxbo4I8CgAQAAAAAAAAAAAAAAAAAAAAAAAJACAASABPAFMAVAAvADEAMAAuADMALgA2ADMALgAyADMANwAAAAAAAAAAAOtG7gHRH3EZyl+55rg3eug=";
            Assert.Equal(b64Authenticate, b64challengeResponseBytes);
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
            Assert.True(SpansAreEqual(new byte[] { 0xa7, 0xc1, 0x5c, 0x5d, 0x97, 0x33, 0x5a, 0x7c }, challenge.ServerChallenge.Span));
            Assert.Equal("DANVMCLOUD", challenge.TargetInfo.NetBiosDomainName);
            Assert.Equal("OP-AGENT-2", challenge.TargetInfo.NetBiosComputerName);
            Assert.Equal("dan.vmcloud", challenge.TargetInfo.DnsDomainName);
            Assert.Equal("op-agent-2.dan.vmcloud", challenge.TargetInfo.DnsComputerName);
            Assert.Equal("dan.vmcloud", challenge.TargetInfo.DnsTreeName);
            var dateTime = DateTime.FromFileTime(challenge.TargetInfo.Timestamp);
            var dateTimeStr = dateTime.ToString("o");
            Assert.Equal("2025-05-29T13:43:20.7972868-06:00", dateTimeStr);
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