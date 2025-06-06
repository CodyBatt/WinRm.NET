namespace WinRm.NET.Internal.Basic
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Basic security is not secure. Sends unencrypted payload with Basic
    /// auth header. This is only for testing and development purposes.
    /// </summary>
    /// <param name="winRmProtocol">Parent winrm protocol</param>
    internal sealed class BasicSecurityEnvelope
        : SecurityEnvelope
    {
        private Credentials credentials;

        public BasicSecurityEnvelope(ILogger? logger, Credentials credentials)
            : base(logger)
        {
            this.credentials = credentials;
        }

        public override string User => this.credentials.User;

        public override AuthType AuthType => AuthType.Basic;

        protected async override Task<string> DecodeResponse(HttpResponseMessage response)
        {
            Logger.Dbg("Decoding response with BasicSecurityEnvelope");
            return await response.Content.ReadAsStringAsync();
        }

        protected override void SetContent(HttpRequestMessage request, XmlDocument soapDocument)
        {
            Logger.Dbg("Setting request content");
            request.Content = new StringContent(soapDocument.OuterXml, Encoding.UTF8, "application/soap+xml");
        }

        protected override void SetHeaders(HttpRequestHeaders headers)
        {
            var authenticationString = $"{credentials.User}:{credentials.Password ?? string.Empty}";
            var base64EncodedAuthenticationString = Convert.ToBase64String(Encoding.UTF8.GetBytes(authenticationString));
            headers.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);
            headers.Add("SOAPAction", string.Empty);
            Logger.Dbg($"Set Basic authentication header: {base64EncodedAuthenticationString}");
        }

        protected override Task HandleErrorResponse(HttpResponseMessage response, StreamContent content)
        {
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                throw new HttpRequestException(Messages.UnauthorizedError);
            }

            return base.HandleErrorResponse(response, content);
        }
    }
}