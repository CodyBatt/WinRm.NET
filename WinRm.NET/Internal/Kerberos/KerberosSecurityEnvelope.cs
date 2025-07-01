namespace WinRm.NET.Internal.Kerberos
{
    using System.Buffers.Binary;
    using System.Globalization;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;
    using global::Kerberos.NET;
    using global::Kerberos.NET.Client;
    using global::Kerberos.NET.Configuration;
    using global::Kerberos.NET.Credentials;
    using global::Kerberos.NET.Crypto;
    using global::Kerberos.NET.Entities;
    using Microsoft.Extensions.Logging;
    using WinRm.NET.Internal.Ntlm;
    using WinRm.NET.Internal.Ntlm.Http;

    internal sealed class KerberosSecurityEnvelope : SecurityEnvelope
    {
        private readonly Credentials credentials;
        private readonly string realmName;
        private readonly string kdcAddress;
        private string? targetSpn;
        private ILoggerFactory? loggerFactory;

        public KerberosSecurityEnvelope(ILogger? logger, Credentials credentials, string realm, string kdc, string? spn)
            : base(logger)
        {
            this.credentials = credentials;
            realmName = realm.ToUpper(CultureInfo.InvariantCulture);
            kdcAddress = kdc;
            targetSpn = spn;
        }

        public override string User => this.credentials.User;

        public override AuthType AuthType => AuthType.Kerberos;

        private WinRmSessionContext? SessionContext { get; set; }

        private KerberosCryptoTransformer? Encryptor { get; set; }

        private KrbEncryptionKey? Key { get; set; }

        public void SetLoggerFactory(ILoggerFactory loggerFactory)
        {
            this.loggerFactory = loggerFactory;
        }

        public async override Task Initialize(WinRmProtocol winRmProtocol)
        {
            await base.Initialize(winRmProtocol);

            var krb5Conf = new Krb5Config
            {
                Defaults =
                {
                    DefaultRealm = realmName,
                    DnsLookupKdc = false,
                    DefaultCCacheName = "MEMORY:",
                },
            };

            var krb5Client = new KerberosClient(krb5Conf, loggerFactory);
            krb5Client.PinKdc(realmName, kdcAddress);

            var creds = new KerberosPasswordCredential(credentials.User, credentials.Password);
            await krb5Client.Authenticate(creds);

            var apOptions = ApOptions.ChannelBindingSupported | ApOptions.MutualRequired;
            var targetHost = winRmProtocol.Endpoint.Host.ToLowerInvariant();
            if (targetSpn == null)
            {
                targetSpn = $"http/{targetHost}";
            }

            var rst = new RequestServiceTicket
            {
                ApOptions = apOptions,
                ServicePrincipalName = targetSpn,
                Realm = realmName,
                CacheTicket = true,
            };

            // This is the Krb5 context that will be used for this session
            SessionContext = new WinRmSessionContext(await krb5Client.GetServiceTicket(rst));

            // Encode the AP_REQ in GSS-API for transmission via HTTP
            var requestHeaderBuffer = GssApiToken.Encode(new Oid(MechType.KerberosGssApi), SessionContext.ApReq);
            var gssKrb5ApReq = Convert.ToBase64String(requestHeaderBuffer.ToArray());

            using var httpClient = winRmProtocol.HttpClientFactory.CreateClient();
            httpClient.BaseAddress = WinRmProtocol.Endpoint;
            httpClient.Timeout = TimeSpan.FromSeconds(120);

            using var request = new HttpRequestMessage(HttpMethod.Post, winRmProtocol.Endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Kerberos", gssKrb5ApReq);
            using var response = await httpClient.SendAsync(request);

            if (!response.Headers.TryGetValues("WWW-Authenticate", out var values))
            {
                throw new InvalidOperationException("[PROTOCOL_ERROR] WWW-Authenticate header not found in response.");
            }

            var gssKrb5ApRep = values.FirstOrDefault()?.Replace("Kerberos", string.Empty).Trim();
            if (string.IsNullOrEmpty(gssKrb5ApRep))
            {
                throw new InvalidOperationException("[PROTOCOL_ERROR] Got WWW-Authenticate, but it did not contain a Kerberos response.");
            }

            // Decode from GSS-API to get to the AP_REP
            var responseHeaderBuffer = Convert.FromBase64String(gssKrb5ApRep);
            var gssToken = GssApiToken.Decode(responseHeaderBuffer);

            // The key returned here is the server session subkey, which is used to encrypt/decrypt WinRM messages
            Key = SessionContext.AuthenticateServiceResponse(gssToken.Token);
            Encryptor = CryptoService.CreateTransform(SessionContext.ApReq.Authenticator.EType);
        }

        protected override async Task<string> DecodeResponse(HttpResponseMessage response)
        {
            if (Encryptor == null)
            {
                throw new InvalidOperationException("Encryptor is not initialized. Ensure Initialize has been called successfully.");
            }

            if (Key == null)
            {
                throw new InvalidOperationException("Encryption Key is not initialized. Ensure Initialize has been called successfully.");
            }

            var responseContent = response.Content;
            if (!responseContent.Headers.ContentType?.MediaType?.StartsWith("multipart") ?? false)
            {
                throw new InvalidOperationException($"Expected multipart response data. Got '{response.Content.Headers.ContentType}'");
            }

            var contentStream = await responseContent.ReadAsStreamAsync();
            var sspContent = new SspMultipartParser(contentStream);

            var sb = new StringBuilder();
            var payload = sspContent.EncryptedDatas.FirstOrDefault();

            if (payload == null)
            {
                throw new InvalidOperationException("No encrypted data found in the response.");
            }

            var gss = new Gss(Encryptor);
            return Encoding.UTF8.GetString(gss.UnWrap(payload, x => this.Key.AsKey()).Span);
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            if (Encryptor == null)
            {
                throw new InvalidOperationException("Encryptor is not initialized. Ensure Initialize has been called successfully.");
            }

            if (Key == null)
            {
                throw new InvalidOperationException("Encryption Key is not initialized. Ensure Initialize has been called successfully.");
            }

            if (SessionContext?.SequenceNumber == null)
            {
                throw new InvalidOperationException("Sequence number is not set. Ensure Initialize has been called successfully.");
            }

            var plaintext = Encoding.UTF8.GetBytes(soapDocument.OuterXml);
            var gss = new Gss(Encryptor);
            var token = gss.Wrap(plaintext, (ulong)SessionContext.SequenceNumber.Value, x => this.Key.AsKey());

            // Build payload: HEADER_LEN | SIGNATURE | SEALED_MESSAGE
            // SIGNATURE is WrapToken + BYTES : ID | FLAGS | FILLER | EC | RCC | SEQ_NUM | "SIGNATURE"
            int headerLength = token.Signature.Length;
            int dataOffset = headerLength + 4;
            Memory<byte> payload = new byte[plaintext.Length + dataOffset];
            BinaryPrimitives.WriteInt32LittleEndian(payload.Span, headerLength);

            token.Signature.CopyTo(payload.Slice(4));
            token.SealedMessage.CopyTo(payload.Slice(dataOffset));

            request.Content = new SspContent(payload, plaintext.Length, "application/HTTP-Kerberos-session-encrypted");
            SessionContext.SequenceNumber++;
        }

        protected override void SetHeaders(HttpRequestHeaders headers)
        {
            // Nothing to do here
        }
    }
}
