namespace WinRm.NET.Internal.Ntlm
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using System.Xml;
    using global::Kerberos.NET.Entities;
    using Microsoft.Extensions.Logging;

    internal sealed class NtlmSecurityEnvelope : SecurityEnvelope
    {
        private Credentials credentials;

        public NtlmSecurityEnvelope(ILogger? logger, Credentials credentials)
            : base(logger)
        {
            this.credentials = credentials;
        }

        public override string User => this.credentials.User;

        public override AuthType AuthType => AuthType.Ntlm;

        private NtlmEncryptor? Encryptor { get; set; }

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
            var request = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", token);
            var response = await client.SendAsync(request);
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
                var challengeResponse = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
                challengeResponse.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", challengeResponseBytes.Span.ToBase64());
                var authenticateResponse = await client.SendAsync(challengeResponse);
                if (!authenticateResponse.IsSuccessStatusCode)
                {
                    throw new HttpRequestException($"NTLM authentication failed with status code: {authenticateResponse.StatusCode}");
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

            throw new NotImplementedException();
        }

        protected override void SetHeaders(HttpRequestHeaders headers)
        {
            throw new NotImplementedException();
        }
    }
}