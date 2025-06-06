namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using WinRm.NET.Internal.Crypto;

    internal class NtlmEncryptor
    {
        private SealingHandle client;
        private SealingHandle server;

        public NtlmEncryptor(ReadOnlyMemory<byte> key)
        {
            ClientSealingKey = NtlmCrypto.ComputeKey(key, client: true, signing: false);
            ClientSigningKey = NtlmCrypto.ComputeKey(key, client: true, signing: true);

            ServerSealingKey = NtlmCrypto.ComputeKey(key, client: false, signing: false);
            ServerSigningKey = NtlmCrypto.ComputeKey(key, client: false, signing: true);

            client = new SealingHandle(ClientSealingKey, ClientSigningKey);
            server = new SealingHandle(ServerSealingKey, ServerSigningKey);
        }

        public NtlmEncryptor(ReadOnlyMemory<byte> clientSealingKey,
            ReadOnlyMemory<byte> serverSealingKey,
            ReadOnlyMemory<byte> clientSigningKey,
            ReadOnlyMemory<byte> serverSigningKey)
        {
            ClientSealingKey = clientSealingKey;
            ClientSigningKey = clientSigningKey;

            ServerSealingKey = serverSealingKey;
            ServerSigningKey = serverSigningKey;

            client = new SealingHandle(ClientSealingKey, ClientSigningKey);
            server = new SealingHandle(ServerSealingKey, ServerSigningKey);
        }

        public SealingHandle Client => client;

        public SealingHandle Server => server;

        internal ReadOnlyMemory<byte> ClientSealingKey { get; }

        internal ReadOnlyMemory<byte> ClientSigningKey { get; }

        internal ReadOnlyMemory<byte> ServerSealingKey { get; }

        internal ReadOnlyMemory<byte> ServerSigningKey { get; }
    }

    internal class SealingHandle
    {
        private Arc4 encryptor;
        private ReadOnlyMemory<byte> signingKey;

        public SealingHandle(ReadOnlyMemory<byte> sealingKey, ReadOnlyMemory<byte> signingKey)
        {
            encryptor = new Arc4(sealingKey);
            this.signingKey = signingKey;
        }

        public ReadOnlyMemory<byte> Transform(ReadOnlySpan<byte> plaintext)
        {
            Memory<byte> ciphertext = new byte[plaintext.Length];
            encryptor.ProcessBytes(plaintext, ciphertext.Span);
            return ciphertext;
        }

        public ReadOnlyMemory<byte> ComputeSignature(int sequenceNumber, ReadOnlySpan<byte> message)
        {
            var seqNumBytes = BitConverter.GetBytes(sequenceNumber);

            var bytes = new List<byte>();
            // Version = 0x00000001 (4 bytes)
            bytes.AddRange(BitConverter.GetBytes((int)1));

            // data = ConcatenationOf(SeqNum, Message)
            var data = new List<byte>();
            data.AddRange(seqNumBytes);
            data.AddRange(message);

            // Checksum = RC4(Handle, HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7])
            // RC4 only the first 8 bytes of the HMAC_MD5
            var hmacMd5 = NtlmCrypto.HMAC_MD5(signingKey, data.ToArray()).Slice(0, 8).Span;
            var checksum = Transform(hmacMd5);

            // Checksum (8 bytes)
            bytes.AddRange(checksum.Span);

            // SeqNum (4 bytes)
            bytes.AddRange(seqNumBytes);

            // Signature bytes (16 bytes)
            return bytes.ToArray();
        }
    }
}