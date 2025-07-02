namespace WinRm.NET.Internal.Kerberos
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using global::Kerberos.NET.Crypto;
    using WinRm.NET.Internal.Http;

    internal class Gss(KerberosCryptoTransformer cipher)
    {
        // MS-KILE 3.4.5.4.1
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550

        // Pad: For AES-SHA1 ciphers using GSS_WrapEx, the extra count (EC) must not be zero.
        // The sender should set extra count (EC) to 1 block - 16 bytes. The recipient must
        // follow the extra count (EC) field in the wrap header to know how many of the decrypted
        // bytes are just padding and must be discarded from the result.
        private const int Ec = 0; // Extra count

        // The RRC field ([RFC4121] section 4.2.5) is 12 if no encryption is requested or 28 if encryption is requested.
        // The RRC field is chosen such that all the data can be encrypted in place. The trailing meta-data H1 is
        // rotated by RRC+EC bytes, which is different from RRC alone. Thus, the token buffer contains the header
        // ([RFC4121] section 4.2.6.2) with the rotated H1 that is placed before the encrypted confounder and
        // after the header.
        private const int Rrc = 28; // Right rotation count

        public bool SentByAcceptor { get; set; }

        public bool Sealed { get; set; } = true;

        public bool AcceptorSubKey { get; set; } = true;

        public (ReadOnlyMemory<byte> SealedMessage, ReadOnlyMemory<byte> Signature) Wrap(ReadOnlyMemory<byte> data, ulong sequenceNumber, Func<Gss, KerberosKey> keyResolver)
        {
            // I don't know why this is 0, but that's what the MS client does and it works.
            // Setting this to zero contradicts the MS-KILE documentation above.

            //ushort paddingLength = (ushort)((this.cipher.BlockSize - (this.data.Length % this.cipher.BlockSize)) & 15);
            ushort paddingLength = 0;
            var padding = Enumerable.Repeat<byte>(0xFF, paddingLength).ToArray();

            // Create a wrap token with Rrc set to 0 which is included in encrypted data.
            var wrapToken = new WrapToken
            {
                TokenId = TokenId.KrbTokenCfxWrap,
                Ec = paddingLength,
                Rrc = 0,
                SequenceNumber = sequenceNumber,
                SentByAcceptor = this.SentByAcceptor,
                Sealed = this.Sealed,
                AcceptorSubKey = this.AcceptorSubKey,
            };
            var tokenBytes = wrapToken.GetBytes();

            // We have data, padding and token bytes to encrypt, copy them all into a new buffer.
            var bytes = new Memory<byte>(new byte[data.Length + paddingLength + tokenBytes.Length]);
            data.CopyTo(bytes);
            padding.CopyTo(bytes.Span[data.Length..]);
            var tokenOffset = data.Length + paddingLength;
            tokenBytes.CopyTo(bytes[tokenOffset..]);

            // Encrypt the payload DATA | PADDING | WRAP_TOKEN
            var cipherText = cipher.Encrypt(bytes, keyResolver(this), KeyUsage.InitiatorSeal);

            // Apply the rotation to the ciphertext
            wrapToken.Rrc = Rrc;
            cipherText = Rotate(cipherText.Span, wrapToken.Rrc + wrapToken.Ec);

            // Get a new wrap token with the correct RRC set
            tokenBytes = wrapToken.GetBytes();

            // The signature is the wrap token bytes + the rotated ciphertext up to the offset (RCC + EC)
            var offset = tokenBytes.Length + wrapToken.Rrc + wrapToken.Ec;
            var signatureBytes = new Memory<byte>(new byte[WrapToken.Length + offset]);
            tokenBytes.CopyTo(signatureBytes);
            cipherText[..offset].CopyTo(signatureBytes[WrapToken.Length..]);
            return (cipherText[offset..], signatureBytes);
        }

        public ReadOnlyMemory<byte> UnWrap(EncryptedData data, Func<Gss, KerberosKey> keyResolver)
        {
            var wrapToken = WrapToken.FromBytes(data.Signature);
            this.AcceptorSubKey = wrapToken.AcceptorSubKey;
            this.SentByAcceptor = wrapToken.SentByAcceptor;
            this.Sealed = wrapToken.Sealed;

            var dataPrefixLength = data.Signature.Length - WrapToken.Length - wrapToken.Ec;
            var dataPrefixOffset = data.Signature.Length - dataPrefixLength;
            var rotatedCipherTextLen = dataPrefixLength + data.Data.Length;

            var rotated = new byte[rotatedCipherTextLen];
            data.Signature.Span[dataPrefixOffset..].CopyTo(rotated.AsSpan(0, dataPrefixLength));
            data.Data.Span.CopyTo(rotated.AsSpan(dataPrefixLength, data.Data.Length));
            var cipherText = UnRotate(rotated, wrapToken.Rrc + wrapToken.Ec);

            var plainText = cipher.Decrypt(cipherText, keyResolver(this), KeyUsage.AcceptorSeal);

            var extraBytes = wrapToken.Ec + data.Signature.Length;
            return plainText.Slice(0, plainText.Length - WrapToken.Length);
        }

        internal static Memory<byte> UnRotate(ReadOnlySpan<byte> data, int numBytes)
        {
            numBytes %= data.Length;

            var result = new byte[data.Length];
            data[numBytes..].CopyTo(result);
            data[..numBytes].CopyTo(result.AsSpan(result.Length - numBytes));

            return result;
        }

        internal static Memory<byte> Rotate(ReadOnlySpan<byte> bytes, int numBytes)
        {
            numBytes %= bytes.Length;
            int left = bytes.Length - numBytes;
            var result = new byte[bytes.Length];
            bytes[left..].CopyTo(result);
            bytes[..left].CopyTo(result.AsSpan(bytes.Length - left));
            return result;
        }
    }
}
