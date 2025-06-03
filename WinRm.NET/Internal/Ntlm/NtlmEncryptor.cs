namespace WinRm.NET.Internal.Ntlm
{
    using global::Kerberos.NET.Crypto;
    using WinRm.NET.Internal.Crypto;

    internal class NtlmEncryptor
    {
        private Arc4 encryptor;
        private Arc4 decryptor;

        public NtlmEncryptor(ReadOnlyMemory<byte> key)
        {
            encryptor = new Arc4(key);
            decryptor = new Arc4(key);
        }

        public Stream Encrypt(Stream data)
        {
            return ProcessStream(data, encryptor);
        }

        public Stream Decrypt(Stream input)
        {
            return ProcessStream(input, decryptor);
        }

        private static Stream ProcessStream(Stream data, Arc4 encryptor)
        {
            data.Position = 0;
            var memoryStream = new MemoryStream();
            var streamWriter = new BinaryWriter(memoryStream);
            while (data.CanRead && data.Position < data.Length)
            {
                Memory<byte> buffer = new byte[4096];
                Memory<byte> outputBuffer = new byte[4096];
                int bytesRead = data.Read(buffer.Span);
                if (bytesRead == 0)
                {
                    break; // EOF
                }

                encryptor.ProcessBytes(buffer.Span, outputBuffer.Span);
                streamWriter.Write(outputBuffer.Span.Slice(0, bytesRead));
            }

            return memoryStream;
        }
    }
}