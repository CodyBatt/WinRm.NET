namespace WinRm.NET.Internal.Ntlm
{
    using System.IO;
    using System.Text;
    using System.Text.RegularExpressions;
    using WinRm.NET.Internal.Http;

    // I tried to use the multipart extension methods from
    // Microsoft.AspNet.WebApi.Client, but they blew up when
    // parsing the responses. I decided to manually build one,
    // but need to investigate something better.
    internal partial class SspMultipartParser : IDisposable
    {
        private MemoryStream stream = new MemoryStream();
        private bool disposedValue;

        public SspMultipartParser(Stream contentStream)
        {
            // Read all the content into a new stream so we can seek on it
            contentStream.CopyTo(stream);
            Parse();
        }

        public List<EncryptedData> EncryptedDatas { get; set; } = new List<EncryptedData>();

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    stream.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        private void Parse()
        {
            stream.Position = 0;
            var line = NextLine();
            if (line != SspContent.BoundaryStart)
            {
                throw new InvalidOperationException("Missing start boundary");
            }

            while (true)
            {
                var expectedLength = ParseOriginalContentLength();
                var contentType = NextLine();

                // Position the stream at the encrypted data

                var encryptedPart = new EncryptedData(stream, expectedLength);
                EncryptedDatas.Add(encryptedPart);
                var boundary = NextLine();
                if (boundary == SspContent.BoundaryFinishMarker)
                {
                    break;
                }
            }
        }

        private string NextLine()
        {
            var bytes = new List<byte>();
            var b = stream.ReadByte();
            while (b != '\n')
            {
                bytes.Add((byte)b);
                b = stream.ReadByte();
            }

            bytes.Add((byte)b);

            return Encoding.UTF8.GetString(bytes.ToArray()).TrimEnd();
        }

        private int ParseOriginalContentLength()
        {
            var line = NextLine();

            int retval = 0;
            while (!line.StartsWith(SspContent.BoundaryStart))
            {
                var match = LengthRegex().Match(line);
                if (match.Success && match.Groups.Count == 2)
                {
                    retval = int.Parse(match.Groups[1].ValueSpan);
                }

                line = NextLine();
            }

            return retval;
        }

        [GeneratedRegex(".*Length=(\\d+)")]
        private static partial Regex LengthRegex();
    }
}