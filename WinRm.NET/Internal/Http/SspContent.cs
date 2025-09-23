namespace WinRm.NET.Internal.Http
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
        internal const string Crlf = "\r\n";
        internal const string BoundaryStart = "--Encrypted Boundary";
        internal const string BoundaryFinishMarker = BoundaryStart + "--";
        internal const string BoundaryFinish = BoundaryFinishMarker + Crlf;

        private ReadOnlyMemory<byte> payload;
        private string text;

        public SspContent(ReadOnlyMemory<byte> payload, int originalContentLength, string contentType)
        {
            this.payload = payload;
            var sb = new StringBuilder();
            sb.Append("--Encrypted Boundary" + Crlf);
            sb.Append($"Content-Type: {contentType}" + Crlf);
            sb.Append($"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={originalContentLength}" + Crlf);
            sb.Append("--Encrypted Boundary" + Crlf);
            sb.Append("Content-Type: application/octet-stream" + Crlf);
            text = sb.ToString();

            Headers.ContentType = new SspContentHeader(contentType);
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