namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using WinRm.NET.Internal.Crypto;

    internal class NtlmEncryptor
    {
        private Arc4 encryptor;
        private Arc4 decryptor;

        public NtlmEncryptor(ReadOnlyMemory<byte> key)
        {
            ClientSealingKey = NtlmCrypto.ComputeKey(key, client: true, signing: false);
            ClientSigningKey = NtlmCrypto.ComputeKey(key, client: true, signing: true);

            ServerSealingKey = NtlmCrypto.ComputeKey(key, client: false, signing: false);
            ServerSigningKey = NtlmCrypto.ComputeKey(key, client: false, signing: true);

            encryptor = new Arc4(ClientSealingKey);
            decryptor = new Arc4(ServerSealingKey);
        }

        internal ReadOnlyMemory<byte> ClientSealingKey { get; }

        internal ReadOnlyMemory<byte> ClientSigningKey { get; }

        internal ReadOnlyMemory<byte> ServerSealingKey { get; }

        internal ReadOnlyMemory<byte> ServerSigningKey { get; }

        public ReadOnlyMemory<byte> ComputeSignature(int sequenceNumber, ReadOnlySpan<byte> message)
        {
            var seqNumBytes = BitConverter.GetBytes(sequenceNumber);

            var bytes = new List<byte>();
            // Version = 0x00000001 (4 bytes)
            bytes.AddRange(BitConverter.GetBytes((int)1));

            // data = ConcatenationOf(SeqNum, Message)
            byte[] data = new byte[message.Length + 4];
            seqNumBytes.CopyTo(data, 0);
            message.CopyTo(data.AsSpan().Slice(4));

            // Checksum = RC4(Handle, HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7])
            // RC4 only the first 8 bytes of the HMAC_MD5
            var hmacMd5 = NtlmCrypto.HMAC_MD5(ClientSigningKey, data).Slice(0, 8).Span;
            var checksum = Encrypt(hmacMd5);

            // Checksum (8 bytes)
            bytes.AddRange(checksum.Span);

            // SeqNum (4 bytes)
            bytes.AddRange(seqNumBytes);

            // Signature bytes (16 bytes)
            return bytes.ToArray();
        }

        public ReadOnlyMemory<byte> Encrypt(ReadOnlySpan<byte> plaintext)
        {
            Memory<byte> ciphertext = new byte[plaintext.Length];
            encryptor.ProcessBytes(plaintext, ciphertext.Span);
            return ciphertext;
        }

        public ReadOnlyMemory<byte> Decrypt(ReadOnlySpan<byte> ciphertext)
        {
            Memory<byte> plaintext = new byte[ciphertext.Length];
            decryptor.ProcessBytes(ciphertext, plaintext.Span);
            return plaintext;
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