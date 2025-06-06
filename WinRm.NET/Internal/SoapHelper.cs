namespace WinRm.NET.Internal
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Xml;

    /// <summary>
    /// Creates SOAP requests in the low budget string formatting way.
    /// Someday we can get serious and use WSDL generated code for this.
    /// </summary>
    internal static class SoapHelper
    {
        internal const string ResourceShell = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

        internal const string ActionCreateShell = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
        internal const string ActionCommand = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
        internal const string ActionReceive = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
        internal const string ActionSignal = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
        internal const string ActionDeleteShell = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

        internal const string CodeCtrlC = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c";

        internal const string AddressAnonymous = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

        internal const string S = "s";
        internal const string Wsa = "wsa";
        internal const string Wsman = "wsman";
        internal const string Rsp = "rsp";
        internal const string Xsi = "xsi";

        internal static Dictionary<string, string> Xmlns { get; } = new Dictionary<string, string>
        {
            { S, "http://www.w3.org/2003/05/soap-envelope" },
            { Wsa, "http://schemas.xmlsoap.org/ws/2004/08/addressing" },
            { Wsman, "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" },
            { Rsp, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell" },
            { Xsi, "http://www.w3.org/2001/XMLSchema-instance" },
        };

        public static void PopulateNamespaces(XmlNamespaceManager xmlNamespaceManager)
        {
            foreach (var ns in Xmlns)
            {
                xmlNamespaceManager.AddNamespace(ns.Key, ns.Value);
            }
        }

        public static string CreateOpenShellSoapRequest(IEnumerable<KeyValuePair<string, string>>? environmentVariables = null)
        {
            var headerOptionSet = @$"<wsman:OptionSet {InsertNamespace(Xsi)}>
                <wsman:Option Name=""WINRS_NOPROFILE"">TRUE</wsman:Option>
                <wsman:Option Name=""WINRS_CODEPAGE"">437</wsman:Option>
                </wsman:OptionSet>";

            var preamble = @$"<s:Envelope
                {BuildXmlNamespaces()}>
                {BuildHeader(ResourceShell, ActionCreateShell, headerOptionSet)}
                <s:Body>
                <rsp:Shell 
                {InsertNamespace(Rsp)}>";

            var sb = new StringBuilder();
            sb.Append(preamble);
            if (environmentVariables != null && environmentVariables.Any())
            {
                sb.AppendLine("<rsp:Environment>");
                foreach (var variable in environmentVariables)
                {
                    sb.AppendLine($"<rsp:Variable Name=\"{variable.Key}\">{variable.Value}</rsp:Variable>");
                }

                sb.AppendLine("</rsp:Environment>");
            }

            // sb.AppendLine($"<rsp:WorkingDirectory>{workingDir}</rsp:WorkingDirectory>");
            sb.AppendLine("<rsp:IdleTimeout>PT10.000S</rsp:IdleTimeout>");
            sb.AppendLine("<rsp:InputStreams>stdin</rsp:InputStreams>");
            sb.AppendLine("<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>");
            sb.AppendLine(@"</rsp:Shell></s:Body></s:Envelope>");
            return sb.ToString();
        }

        public static string CreateExecuteCommandSoapRequest(string shellId, string command, IEnumerable<string>? arguments = null)
        {
            var headerOptionSet = @$"<wsman:OptionSet {InsertNamespace(Xsi)}>
                <wsman:Option Name=""WINRS_CONSOLEMODE_STDIN"">TRUE</wsman:Option>
                <wsman:Option Name=""WINRS_SKIP_CMD_SHELL"">FALSE</wsman:Option>
                </wsman:OptionSet>";

            var preamble = @$"<s:Envelope
                {BuildXmlNamespaces()}>
                {BuildHeader(ResourceShell, ActionCommand, headerOptionSet, shellId: shellId)}
                <s:Body>
                <rsp:CommandLine 
                {InsertNamespace(Rsp)}>";

            var sb = new StringBuilder();
            sb.Append(preamble);

            sb.AppendLine($"<rsp:Command>{command}</rsp:Command>");
            if (arguments != null)
            {
                foreach (var arg in arguments)
                {
                    sb.AppendLine($"<rsp:Arguments>{arg}</rsp:Arguments>");
                }
            }

            sb.AppendLine(@"</rsp:CommandLine></s:Body></s:Envelope>");
            return sb.ToString();
        }

        public static string CreateReceiveOutputSoapRequest(string shellId, string commandId)
        {
            var preamble = @$"<s:Envelope
                {BuildXmlNamespaces()}>
                {BuildHeader(ResourceShell, ActionReceive, shellId: shellId)}
                <s:Body>
                <rsp:Receive 
                {InsertNamespace(Rsp)}>";

            var sb = new StringBuilder();
            sb.Append(preamble);

            sb.Append($"<rsp:DesiredStream CommandId=\"{commandId.ToString().ToUpperInvariant()}\">");
            sb.Append("stdout stderr");
            sb.Append("</rsp:DesiredStream>");

            sb.AppendLine(@"</rsp:Receive></s:Body></s:Envelope>");
            return sb.ToString();
        }

        public static string CreateTerminateOperationSoapRequest(string shellId, string commandId)
        {
            var preamble = @$"<s:Envelope
                {BuildXmlNamespaces()}>
                {BuildHeader(ResourceShell, ActionSignal, shellId: shellId)}
                <s:Body>
                <rsp:Signal {InsertNamespace(Rsp)} CommandId=""{commandId.ToString()}"">";

            var sb = new StringBuilder();
            sb.Append(preamble);
            sb.Append($"<rsp:Code>{CodeCtrlC}</rsp:Code>");
            sb.AppendLine(@"</rsp:Signal></s:Body></s:Envelope>");
            return sb.ToString();
        }

        public static string CreateDeleteShellSoapRequest(string shellId)
        {
            return @$"<s:Envelope
                {BuildXmlNamespaces()}>
                {BuildHeader(ResourceShell, ActionDeleteShell, shellId: shellId)}
                <s:Body></s:Body></s:Envelope>";
        }

        private static string BuildHeader(string resourceUri, string action, string? extraHeaderInfo = null, string? shellId = null, string? messageId = null)
        {
            var messageIdValue = messageId ?? Guid.NewGuid().ToString().ToUpperInvariant();

            var sb = new StringBuilder();
            sb.AppendLine("<s:Header>");
            sb.AppendLine("<wsa:To>http://windows-host:5985/wsman</wsa:To>");
            sb.AppendLine($"<wsa:ReplyTo><wsa:Address s:mustUnderstand=\"true\">{AddressAnonymous}</wsa:Address></wsa:ReplyTo>");
            sb.AppendLine("<wsman:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</wsman:MaxEnvelopeSize>");
            sb.AppendLine($"<wsa:MessageID>uuid:{messageIdValue}</wsa:MessageID>");
            sb.AppendLine("<wsman:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\" />");
            sb.AppendLine("<wsman:OperationTimeout>PT120.000S</wsman:OperationTimeout>");
            sb.AppendLine($"<wsman:ResourceURI s:mustUnderstand=\"true\">{resourceUri}</wsman:ResourceURI>");
            sb.AppendLine($"<wsa:Action s:mustUnderstand=\"true\">{action}</wsa:Action>");
            if (!string.IsNullOrEmpty(shellId))
            {
                sb.AppendLine($"<wsman:SelectorSet><wsman:Selector Name=\"ShellId\">{shellId}</wsman:Selector></wsman:SelectorSet>");
            }

            if (!string.IsNullOrEmpty(extraHeaderInfo))
            {
                sb.AppendLine(extraHeaderInfo);
            }

            sb.AppendLine("</s:Header>");
            return sb.ToString();
        }

        private static string BuildXmlNamespaces()
        {
            var sb = new StringBuilder();
            foreach (var ns in Xmlns)
            {
                sb.AppendLine($"xmlns:{ns.Key}=\"{ns.Value}\" ");
            }

            return sb.ToString();
        }

        private static string InsertNamespace(string namespaceKey)
        {
            return $"xmlns:{namespaceKey}=\"{Xmlns[namespaceKey]}\"";
        }
    }
}
