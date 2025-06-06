namespace WinRm.NET.Internal
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using System.Xml;
    using Microsoft.Extensions.Logging;

    internal abstract class SecurityEnvelope : ISecurityEnvelope
    {
        public SecurityEnvelope(ILogger? logger)
        {
            this.Logger = logger;
        }

        public abstract string User { get; }

        public abstract AuthType AuthType { get; }

        protected WinRmProtocol? WinRmProtocol { get; private set; }

        protected ILogger? Logger { get; }

        [MemberNotNull("WinRmProtocol")]
        public virtual Task Initialize(WinRmProtocol winRmProtocol)
        {
            this.WinRmProtocol = winRmProtocol;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Send the SOAP message and handle errors. If successful,
        /// return the response as an XmlDocument. Derived classes are responsible
        /// for setting up the authorization headers and encrypting/decrypting the
        /// payloads.
        /// </summary>
        /// <param name="soapDocument">The SOAP request document</param>
        /// <returns>XmlDocument response</returns>
        public async Task<XmlDocument> SendMessage(XmlDocument soapDocument)
        {
            if (this.WinRmProtocol == null)
            {
                throw new InvalidOperationException("Security envelope is not initialized. Call Initialize() first.");
            }

            using var client = this.WinRmProtocol.HttpClientFactory.CreateClient();
            client.BaseAddress = this.WinRmProtocol.Endpoint;
            client.Timeout = TimeSpan.FromSeconds(120); // Hard-coded 2 minute timeout in case no one is home

            using var request = new HttpRequestMessage(HttpMethod.Post, this.WinRmProtocol.Endpoint);
            request.Headers.Add("User-Agent", "WinRM.NET");
            request.Headers.Add("Connection", "Keep-Alive");
            SetHeaders(request.Headers);
            SetContent(request, soapDocument);
            using var response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                // TODO: pywinrm checks for all these soap faults, which we should do too
                // if there are stupid problems we should maybe retry here as well. I know we have
                // seen some stupid things like "local error occurred" which we can probably retry
                // successfully.

                //    fault = root.find("soapenv:Body/soapenv:Fault", xmlns)
                //if fault is None:
                //    raise

                //wsmanfault_code_raw = fault.find("soapenv:Detail/wsmanfault:WSManFault[@Code]", xmlns)
                //wsmanfault_code: int | None = None
                //if wsmanfault_code_raw is not None:
                //    wsmanfault_code = int(wsmanfault_code_raw.attrib["Code"])

                //    # convert receive timeout code to WinRMOperationTimeoutError
                //    if wsmanfault_code == 2150858793:
                //        # TODO: this fault code is specific to the Receive operation; convert all op timeouts?
                //        raise WinRMOperationTimeoutError()

                //fault_code_raw = fault.find("soapenv:Code/soapenv:Value", xmlns)
                //fault_code: str | None = None
                //if fault_code_raw is not None and fault_code_raw.text:
                //    fault_code = fault_code_raw.text

                //fault_subcode_raw = fault.find("soapenv:Code/soapenv:Subcode/soapenv:Value", xmlns)
                //fault_subcode: str | None = None
                //if fault_subcode_raw is not None and fault_subcode_raw.text:
                //    fault_subcode = fault_subcode_raw.text

                //error_message_node = fault.find("soapenv:Reason/soapenv:Text", xmlns)
                //reason: str | None = None
                //if error_message_node is not None:
                //    reason = error_message_node.text

                //wmi_error_code_raw = fault.find("soapenv:Detail/wmierror:MSFT_WmiError/wmierror:error_Code", xmlns)
                //wmi_error_code: int | None = None
                //if wmi_error_code_raw is not None and wmi_error_code_raw.text:
                //    wmi_error_code = int(wmi_error_code_raw.text)

                var responseContent = await DecodeResponse(response);
                var xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(responseContent);
                return xmlDocument;
            }
            else
            {
                var streamContent = new StreamContent(response.Content.ReadAsStream());

                // This will either throw or do nothing
                await HandleErrorResponse(response, streamContent);

                var responseData = await streamContent.ReadAsStringAsync();

                // TODO: Define specific exceptions that we will throw from WinRm.NET
                throw new HttpRequestException($"Error: {response.StatusCode}, {response.ReasonPhrase} SOAP Response: {responseData}");
            }
        }

        public async ValueTask DisposeAsync()
        {
            // Perform async cleanup.
            await DisposeAsyncCore();

            // Dispose of unmanaged resources. Do we need this?
            // Dispose(false);

            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        protected virtual Task HandleErrorResponse(HttpResponseMessage response, StreamContent content)
        {
            return Task.CompletedTask;
        }

        protected abstract void SetHeaders(HttpRequestHeaders headers);

        protected abstract void SetContent(HttpRequestMessage request, XmlDocument soapDocument);

        protected abstract Task<string> DecodeResponse(HttpResponseMessage response);

        protected virtual ValueTask DisposeAsyncCore()
        {
            // For whatever cleanup is needed, override this method in derived classes.
            return ValueTask.CompletedTask;
        }
    }
}
