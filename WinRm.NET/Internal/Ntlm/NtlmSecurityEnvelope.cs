namespace WinRm.NET.Internal.Ntlm
{
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;
    using global::Kerberos.NET.Entities;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Primitives;

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

        // private AuthenticationHeaderValue? AuthenticationHeader { get; set; }

        public override async Task Initialize(WinRmProtocol winRmProtocol)
        {
            await base.Initialize(winRmProtocol);

            using var client = winRmProtocol.HttpClientFactory.CreateClient();
            client.BaseAddress = WinRmProtocol.Endpoint;
            client.Timeout = TimeSpan.FromSeconds(120);

            // Create NTLMSSP negotiate header
            var negotiate = new NtlmNegotiate();
            negotiate.Flags = NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE
                | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH
                | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56;

            var negotiateBytes = negotiate.GetBytes();
            Log.Dbg(Logger, $"Negotiate: {negotiateBytes.Span.ToHexString()}");
            var token = negotiateBytes.Span.ToBase64();
            using var request = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", token);
            using var response = await client.SendAsync(request);
            // Deal with the challenge response
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                Logger.Dbg("Received 401 Unauthorized, processing NTLM challenge.");
                if (!response.Headers.TryGetValues("WWW-Authenticate", out var values))
                {
                    throw new InvalidOperationException("WWW-Authenticate header not found in response.");
                }

                var challengeMessage = values.First().Replace("Negotiate ", string.Empty).Trim();
                var challengeBytes = Convert.FromBase64String(challengeMessage);
                var challenge = new NtlmChallenge(challengeBytes);
                var clientChallenge = challenge.GetClientChallenge();

                // Initialize authenticate message
                NtlmAuthenticate auth = new NtlmAuthenticate();
                auth.UserName = credentials.User;
                auth.DomainName = credentials.Domain;
                auth.Workstation = System.Environment.MachineName;
                auth.SetFlags(challenge.Flags);

                // Compute the key exchange data
                var randomSessionKey = NtlmCrypto.CreateRandomSessionKey();
                var responseKeyNt = NtlmCrypto.ResponseKeyNt(credentials);
                var ntProofStr = NtlmCrypto.NtProofString(responseKeyNt, challenge.ServerChallenge, clientChallenge.GetBytesPadded());

                auth.NtChallengeResponse = clientChallenge.GetBytesNtChallengeResponse(ntProofStr);
                var sessionBaseKey = NtlmCrypto.SessionBaseKey(responseKeyNt, ntProofStr);
                var kxkey = NtlmCrypto.KXKEY(auth.NegotiationFlags, sessionBaseKey);
                auth.EncryptedRandomSessionKey = NtlmCrypto.TransformRandomSessionKey(kxkey, randomSessionKey);

                // Set the MIC
                var authenticateBytes = auth.GetBytes();
                auth.MIC = NtlmCrypto.CalculateMic(randomSessionKey, negotiateBytes, challengeBytes, authenticateBytes);

                // Get bytes again after setting MIC
                var challengeResponseBytes = auth.GetBytes(forceBuild: true);
                using var challengeResponse = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
                challengeResponse.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", challengeResponseBytes.Span.ToBase64());
                using var authenticationResponse = await client.SendAsync(challengeResponse);
                if (!authenticationResponse.IsSuccessStatusCode)
                {
                    throw new InvalidOperationException("Authentication failed");
                }

                Encryptor = new NtlmEncryptor(randomSessionKey);
            }
        }

        protected override Task<string> DecodeResponse(HttpResponseMessage response)
        {
            if (Encryptor == null)
            {
                throw new InvalidOperationException("Encryptor is not initialized. Ensure Initialize has been called successfully.");
            }

            throw new NotImplementedException();
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            if (Encryptor == null)
            {
                throw new InvalidOperationException("Encryptor is not initialized. Ensure Initialize has been called successfully.");
            }

            var plaintext = Encoding.UTF8.GetBytes(soapDocument.OuterXml);
            ReadOnlyMemory<byte> ciphertext = Encryptor.Encrypt(plaintext);
            ReadOnlyMemory<byte> signature = Encryptor.ComputeSignature(sequenceNumber, plaintext);

            // Build payload: SIGNATURE_LEN | SIGNATURE | ENCRYPTED_DATA
            int signatureLength = signature.Length;
            int dataOffset = signatureLength + 4;
            Memory<byte> payload = new byte[plaintext.Length + dataOffset];
            BitConverter.GetBytes((int)signatureLength).CopyTo(payload.Span);
            signature.CopyTo(payload.Slice(4));
            ciphertext.CopyTo(payload.Slice(dataOffset));
            this.sequenceNumber++;

            var content = new GssContent(payload);
            request.Content = content;
        }

        protected override void SetHeaders(HttpRequestHeaders headers)
        {
        }
    }

    // These content classes can probably be replaced once this is working
    // I'm just using them so that our HTTP request looks
    // like Microsoft's in terms of newlines and formatting to eliminate
    // variance.
    internal class GssContent : HttpContent
    {
        //var content = new MultipartContent("encrypted", "Encrypted Boundary");
        //var contentTypeHeader = new MediaTypeHeaderValue("multipart/encrypted");
        //contentTypeHeader.Parameters.Add(new NameValueHeaderValue("protocol", "\"application/HTTP-SPNEGO-session-encrypted\""));
        //contentTypeHeader.Parameters.Add(new NameValueHeaderValue("boundary", "\"Encrypted Boundary\""));

        //var originalDataContent = new StringContent(string.Empty);
        //originalDataContent.Headers.ContentType = new MediaTypeHeaderValue("application/HTTP-SPNEGO-session-encrypted");
        //originalDataContent.Headers.Add("OriginalContent", $"application/soap+xml;charset=UTF-8;Length={plaintext.Length}");
        //content.Add(originalDataContent);

        //Log.Dbg(Logger, $"Plaintext:\r\n{soapDocument.OuterXml}");

        //var encryptedContent = new ReadOnlyMemoryContent(payload);
        //encryptedContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        //content.Add(encryptedContent);
        private const string BoundaryFinish = "--Encrypted Boundary--\r\n";

        private ReadOnlyMemory<byte> payload;
        private string text;

        public GssContent(ReadOnlyMemory<byte> payload)
        {
            this.payload = payload;
            var sb = new StringBuilder();
            sb.AppendLine("--Encrypted Boundary");
            sb.AppendLine("Content-Type: application/HTTP-SPNEGO-session-encrypted");
            sb.AppendLine($"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={payload.Length}");
            sb.AppendLine("--Encrypted Boundary");
            sb.AppendLine("Content-Type: application/octet-stream");
            this.text = sb.ToString();

            this.Headers.ContentType = new GssContentHeader();
        }

        protected async override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(this.text));
            await stream.WriteAsync(payload);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(BoundaryFinish));
        }

        protected override bool TryComputeLength(out long length)
        {
            length = this.text.Length + payload.Length + BoundaryFinish.Length;
            return true;
        }
    }

    internal class GssContentHeader : MediaTypeHeaderValue
    {
        public GssContentHeader()
            : base("multipart/encrypted")
        {
        }

        public override string ToString()
        {
            return "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"";
        }
    }
}