namespace WinRm.NET.Internal.Kerberos
{
    using System;
    using System.Text;
    using System.Threading.Tasks;
    using global::Kerberos.NET.Crypto;
    using WinRm.NET.Internal.Ntlm.Http;

    internal class GssUnWrap
    {
        private EncryptedData data;

        public GssUnWrap(KerberosCryptoTransformer cipher, KerberosKey key, EncryptedData data)
        {
            Key = key;
            Cipher = cipher;
            this.data = data;
        }

        public KerberosKey Key { get; private set; }

        public KerberosCryptoTransformer Cipher { get; private set; }

        public ReadOnlyMemory<byte> GetBytes()
        {
            var wrapToken = WrapToken.FromBytes(this.data.Signature);
            var dataPrefixLength = this.data.Signature.Length - WrapToken.Length - wrapToken.Ec;
            var dataPrefixOffset = this.data.Signature.Length - dataPrefixLength;
            var rotatedCipherTextLen = dataPrefixLength + data.Data.Length;

            var rotated = new byte[rotatedCipherTextLen];
            this.data.Signature.Span[dataPrefixOffset..].CopyTo(rotated.AsSpan(0, dataPrefixLength));
            this.data.Data.Span.CopyTo(rotated.AsSpan(dataPrefixLength, this.data.Data.Length));
            var cipherText = UnRotate(rotated, wrapToken.Rrc + wrapToken.Ec);

            var plainText = Cipher.Decrypt(cipherText, this.Key, KeyUsage.AcceptorSeal);

            var extraBytes = wrapToken.Ec + this.data.Signature.Length;
            return plainText.Slice(0, plainText.Length - WrapToken.Length);
        }

        public Task<string> GetString()
        {
            var bytes = GetBytes();
            return Task.FromResult(Encoding.UTF8.GetString(bytes.Span));
        }

        internal static Memory<byte> UnRotate(ReadOnlySpan<byte> data, int numBytes)
        {
            numBytes %= data.Length;

            var result = new byte[data.Length];
            data[numBytes..].CopyTo(result);
            data[..numBytes].CopyTo(result.AsSpan(result.Length - numBytes));

            return result;
        }
    }
}
