namespace WinRmTests
{
    using System;
    using System.Text;
    using WinRm.NET.Internal;
    using WinRm.NET.Internal.Ntlm;

    // This test uses canned values from a real-world packet capture on some test machines.
    // Ensures that we are able to build, parse and compute a real-world NTLMv2 authentication message
    public class NtlmAuthSession
    {
        [Fact]
        public void SimulateNegotiation()
        {
            // These credentials were used in the packet capture and are no longer valid.
            var credentials = new Credentials("cbatt-adm@DAN.VMCLOUD", Encoding.UTF8.GetString(Convert.FromBase64String("cm9vdDRFRE1a")));

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
            Assert.True(Test.SpansAreEqual(expectedServerChallenge, challenge.ServerChallenge.Span));

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
            auth.EncryptedRandomSessionKey = NtlmCrypto.RC4KRandomSessionKey(kxkey, randomSessionKey);
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
    }
}
