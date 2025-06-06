namespace WinRm.NET.Internal.Ntlm.Http
{
    using System.Net.Http.Headers;

    internal class SspContentHeader : MediaTypeHeaderValue
    {
        public SspContentHeader()
            : base("multipart/encrypted")
        {
        }

        public override string ToString()
        {
            return "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"";
        }
    }
}