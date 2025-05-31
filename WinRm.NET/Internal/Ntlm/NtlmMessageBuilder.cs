namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using global::Kerberos.NET.Entities;

    internal sealed partial class NtlmMessageBuilder
    {
        private NtlmNegotiateFlag flags = NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM_V1
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_LM_KEY
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN
            | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
            | NtlmNegotiateFlag.NTLM_NEGOTIATE_OEM
            | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE;

        public NtlmMessageBuilder SetFlag(NtlmNegotiateFlag flag)
        {
            flags |= flag;
            return this;
        }

        public NtlmMessageBuilder ClearFlag(NtlmNegotiateFlag flag)
        {
            flags &= ~flag;
            return this;
        }

        public static byte[] Build(NtlmAuthenticate ntlmAuthenticate)
        {
            List<byte> messageBytes = new List<byte>();

            return messageBytes.ToArray();
        }
    }
}
