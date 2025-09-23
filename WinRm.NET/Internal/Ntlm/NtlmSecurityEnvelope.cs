namespace WinRm.NET.Internal.Ntlm
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;
    using global::Kerberos.NET.Entities;
    using Microsoft.Extensions.Logging;
    using WinRm.NET.Internal.Http;

    internal sealed class NtlmSecurityEnvelope : SecurityEnvelope
    {
        private Credentials credentials;

        private int sequenceNumber;

        public NtlmSecurityEnvelope(ILogger? logger, Credentials credentials)
            : base(logger)
        {
            this.credentials = credentials;
        }

        public override string User => this.credentials.User;

        public override AuthType AuthType => AuthType.Ntlm;

        private NtlmEncryptor? Encryptor { get; set; }

        private AuthenticationHeaderValue? AuthenticationHeader { get; set; }

        public override async Task Initialize(WinRmProtocol winRmProtocol)
        {
            await base.Initialize(winRmProtocol);

            using var client = winRmProtocol.HttpClientFactory.CreateClient();
            client.BaseAddress = WinRmProtocol.Endpoint;
            client.Timeout = TimeSpan.FromSeconds(120);

            // Create NTLMSSP negotiate header
            var negotiate = new NtlmNegotiate();
            negotiate.Flags = NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN // Integrity, Replay Detect, Sequence Detect
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL // Confidentiality
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH // Confidentiality
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_LM_KEY // Confidentiality
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY // Confidentiality
                | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET // Required by spec
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM_V1 // Rquired by spec
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN // Required by spec
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE // Required by spec
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION // Optional, but we set it to match MS
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128; // Use 128-bit keys
                // | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56; // We don't support 56 bit encryption

            var negotiateBytes = negotiate.GetBytes();
            Log.Dbg(Logger, $"Negotiate: {negotiateBytes.Span.ToHexString()}");
            var token = negotiateBytes.Span.ToBase64();
            using var request = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", token);
            using var response = await client.SendAsync(request);
            // Deal with the challenge response
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                if (!response.Headers.TryGetValues("WWW-Authenticate", out var values))
                {
                    throw new InvalidOperationException("[PROTOCOL_ERROR] WWW-Authenticate header not found in response.");
                }

                var challengeMessage = values.FirstOrDefault()?.Replace("Negotiate", string.Empty).Trim();
                if (string.IsNullOrEmpty(challengeMessage))
                {
                    throw new InvalidOperationException("[PROTOCOL_ERROR] Got WWW-Authenticate, but it did not contain a challenge. Check negotiate flags.");
                }

                var challengeBytes = Convert.FromBase64String(challengeMessage);
                Logger.Dbg($"Processing NTLM challenge: {challengeBytes.ToHexString()}");
                var challenge = new NtlmChallenge(challengeBytes);
                if (!challenge.Validate())
                {
                    throw new InvalidOperationException("[PROTOCOL_ERROR] STATUS_LOGON_FAILURE Missing required challenge data.");
                }

                var result = NtlmAuthenticate.CreateAuthenticateMessage(credentials, negotiateBytes, challengeBytes);
                AuthenticationHeader = new AuthenticationHeaderValue("Negotiate", result.ChallengeResponse.Span.ToBase64());
                Encryptor = new NtlmEncryptor(result.SessionKey);
            }
        }

        protected override async Task<string> DecodeResponse(HttpResponseMessage response)
        {
            if (Encryptor == null)
            {
                throw new InvalidOperationException("Encryptor is not initialized. Ensure Initialize has been called successfully.");
            }

            var responseContent = response.Content;
            if (!responseContent.Headers.ContentType?.MediaType?.StartsWith("multipart") ?? false)
            {
                throw new InvalidOperationException($"Expected multipart response data. Got '{response.Content.Headers.ContentType}'");
            }

            var contentStream = await responseContent.ReadAsStreamAsync();
            var sspContent = new SspMultipartParser(contentStream);

            var sb = new StringBuilder();
            foreach (var data in sspContent.EncryptedDatas)
            {
                var decodedData = Encryptor.Server.Transform(data.Data.Span);
                var signature = new SspMessageSignature(data.Signature);
                var computedSignature = Encryptor.Server.ComputeSignature(signature.SequenceNumber, decodedData.Span);
                var expectedSignature = new SspMessageSignature(computedSignature);
                if (signature.CheckSum.Span.ToHexString() != expectedSignature.CheckSum.Span.ToHexString())
                {
                    throw new InvalidOperationException("Invalid checksum");
                }

                sb.Append(Encoding.UTF8.GetString(decodedData.Span));
            }

            return sb.ToString();
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            if (Encryptor == null)
            {
                throw new InvalidOperationException("Encryptor is not initialized. Ensure Initialize has been called successfully.");
            }

            if (AuthenticationHeader != null)
            {
                request.Headers.Authorization = AuthenticationHeader;
                AuthenticationHeader = null;
            }

            var plaintext = Encoding.UTF8.GetBytes(soapDocument.OuterXml);
            ReadOnlyMemory<byte> ciphertext = Encryptor.Client.Transform(plaintext);
            ReadOnlyMemory<byte> signature = Encryptor.Client.ComputeSignature(sequenceNumber, plaintext);

            // Build payload: SIGNATURE_LEN | SIGNATURE | ENCRYPTED_DATA
            int signatureLength = signature.Length;
            int dataOffset = signatureLength + 4;
            Memory<byte> payload = new byte[plaintext.Length + dataOffset];
            BitConverter.GetBytes((int)signatureLength).CopyTo(payload.Span);
            signature.CopyTo(payload.Slice(4));
            ciphertext.CopyTo(payload.Slice(dataOffset));
            this.sequenceNumber++;

            request.Content = new SspContent(payload, plaintext.Length, "application/HTTP-SPNEGO-session-encrypted");
        }

        protected override void SetHeaders(HttpRequestHeaders headers)
        {
        }
    }
}