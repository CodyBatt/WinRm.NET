namespace WinRm.NET.Internal
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml;

    internal sealed class WinRmProtocol
    {
        private WinRmSession parent;
        private ISecurityEnvelope securityEnvelope;

        public WinRmProtocol(WinRmSession parent, ISecurityEnvelope securityEnvelope)
        {
            this.parent = parent;
            this.securityEnvelope = securityEnvelope;
            Endpoint = new Uri($"http://{parent.Host}:5985/wsman");
        }

        public Uri Endpoint { get; }

        internal IHttpClientFactory HttpClientFactory => parent.HttpClientFactory;

        public async Task<string> OpenShell(IEnumerable<KeyValuePair<string, string>>? environmentVariables = null)
        {
            // Generate the CreateShell SOAP Message: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/7f4a1f31-47d8-4599-a23b-c3834ffae21f?redirectedfrom=MSDN
            // All the optional shell properties are here: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/b3dd6257-9326-466b-9fc5-9f788973d40e
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(SoapHelper.CreateOpenShellSoapRequest(environmentVariables));

            // Security envelope will wrap and send the request as well as handle errors
            var response = await securityEnvelope.SendMessage(xmlDocument);

            // Get the shell Id out of the response and return it. The ID is a Guid, but WinRm actually
            // cares about case sensitivity, so we need to make sure we preserve it as-is in a string.
            var xmlns = SoapHelper.Xmlns[SoapHelper.Rsp];
            var shellId = response.GetElementsByTagName("ShellId", xmlns).Item(0)!.InnerText;
            return shellId;
        }

        public async Task<string> ExecuteCommand(string shellId, string command, IEnumerable<string>? arguments = null)
        {
            // Generate the ExecuteCommand SOAP Message: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/d537264b-fda8-4694-a518-ae0085d92441
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(SoapHelper.CreateExecuteCommandSoapRequest(shellId, command, arguments));

            // Security envelope will wrap and send the request as well as handle errors
            var response = await securityEnvelope.SendMessage(xmlDocument);

            // Get the command ID and return it
            var xmlns = SoapHelper.Xmlns[SoapHelper.Rsp];
            var commandId = response.GetElementsByTagName("CommandId", xmlns).Item(0)!.InnerText;
            return commandId;
        }

        public async Task<CommandResult> GetCommandResult(string shellId, string commandId)
        {
            // Generate the ReceiveOutput SOAP Message: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/b8d1b0bd-484e-4ac0-a9dd-9244f13697db
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(SoapHelper.CreateReceiveOutputSoapRequest(shellId, commandId));

            // Security envelope will wrap and send the request as well as handle errors
            var response = await securityEnvelope.SendMessage(xmlDocument);

            var xmlns = new XmlNamespaceManager(response.NameTable);
            SoapHelper.PopulateNamespaces(xmlns);
            CommandResult commandResult = new CommandResult();

            // Get the command state / status code
            var exitCode = response.SelectSingleNode("//ExitCode", xmlns);
            if (exitCode != null)
            {
                commandResult.StatusCode = int.Parse(exitCode.InnerText);
            }

            // Get stdout
            var stdout = response.SelectNodes("//rsp:Stream[@Name='stdout']", xmlns);
            if (stdout != null)
            {
                commandResult.StdOutput = ExtractStream(stdout);
            }

            // Get stderr
            var stderr = response.SelectNodes("//rsp:Stream[@Name='stderr']", xmlns);
            if (stderr != null)
            {
                commandResult.StdError = ExtractStream(stderr);
            }

            return commandResult;
        }

        public async Task TerminateOperation(string shellId, string commandId)
        {
            // Generate the TerminateOperation SOAP Message: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/ded708a2-e24e-4284-aac8-35c14801c21b
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(SoapHelper.CreateTerminateOperationSoapRequest(shellId, commandId));

            // This doesn't return anything useful, so we don't need to parse the response
            await securityEnvelope.SendMessage(xmlDocument);
        }

        public async Task CloseShell(string shellId)
        {
            // Generate the DeleteShell SOAP Message: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/4b133c1c-9102-43eb-83ac-60001cebb4a6
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(SoapHelper.CreateDeleteShellSoapRequest(shellId));

            // This doesn't return anything useful, so we don't need to parse the response
            await securityEnvelope.SendMessage(xmlDocument);
        }

        // Output streams are delivered as a sequence of base64 encoded XML nodes
        // which can span over nodes, so we collect the bytes from each into a list
        // then decode it all at the end.
        private static string ExtractStream(XmlNodeList nodes)
        {
            var bytes = new List<byte>();
            for (int i = 0; i < nodes.Count; i++)
            {
                var node = nodes[i]!;

                if (node.Attributes?.GetNamedItem("End") != null)
                {
                    break;
                }

                bytes.AddRange(Convert.FromBase64String(node.InnerText));
            }

            return Encoding.UTF8.GetString(bytes.ToArray());
        }
    }
}
