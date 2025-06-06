namespace WinRm.NET.Internal.Ntlm.Http
{
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;

    // I couldn't find a way to get the request to look identical to what
    // the microsoft clients are sending, so I manually crafted it with
    // this class. Need to revisit this.
    internal class SspContent : HttpContent
    {
        internal const string BoundaryStart = "--Encrypted Boundary";
        internal const string BoundaryFinishMarker = BoundaryStart + "--";
        internal const string BoundaryFinish = BoundaryFinishMarker + "\r\n";

        private ReadOnlyMemory<byte> payload;
        private string text;

        public SspContent(ReadOnlyMemory<byte> payload)
        {
            this.payload = payload;
            var sb = new StringBuilder();
            sb.AppendLine("--Encrypted Boundary");
            sb.AppendLine("Content-Type: application/HTTP-SPNEGO-session-encrypted");
            // TODO: Fix this. The length should only count the encrypted data, not the encryption header
            sb.AppendLine($"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={payload.Length - 20}");
            sb.AppendLine("--Encrypted Boundary");
            sb.AppendLine("Content-Type: application/octet-stream");
            text = sb.ToString();

            Headers.ContentType = new SspContentHeader();
        }

        protected async override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(text));
            await stream.WriteAsync(payload);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(BoundaryFinish));
        }

        protected override bool TryComputeLength(out long length)
        {
            length = text.Length + payload.Length + BoundaryFinish.Length;
            return true;
        }
    }
}