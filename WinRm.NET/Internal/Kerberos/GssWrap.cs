namespace WinRm.NET.Internal.Kerberos
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.Linq;
    using global::Kerberos.NET.Crypto;

    internal class GssWrap
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

        private readonly KerberosCryptoTransformer cipher;
        private readonly ReadOnlyMemory<byte> data;

        public GssWrap(KerberosCryptoTransformer cipher, KerberosKey key, ReadOnlyMemory<byte> data, ulong sequenceNumber)
        {
            this.cipher = cipher;
            this.data = data;
            this.SequenceNumber = sequenceNumber;
            this.Key = key;
        }

        public KerberosKey Key { get; private set; }

        public TokenId TokenId { get; } = TokenId.KrbTokenCfxWrap;

        public bool SentByAcceptor { get; set; }

        public bool Sealed { get; set; } = true;

        public bool AcceptorSubKey { get; set; } = true;

        private ulong SequenceNumber { get; set; }

        public (ReadOnlyMemory<byte> SealedMessage, ReadOnlyMemory<byte> Signature) GetBytes()
        {
            // I don't know why this is 0, but that's what the MS client does and it works.
            // Setting this to zero contradicts the MS-KILE documentation above.

            //ushort paddingLength = (ushort)((this.cipher.BlockSize - (this.data.Length % this.cipher.BlockSize)) & 15);
            ushort paddingLength = 0;
            var padding = Enumerable.Repeat<byte>(0xFF, paddingLength).ToArray();

            // Create a wrap token with Rrc set to 0 which is included in encrypted data.
            var wrapToken = new WrapToken
            {
                TokenId = this.TokenId,
                Ec = paddingLength,
                Rrc = 0,
                SequenceNumber = this.SequenceNumber,
                SentByAcceptor = this.SentByAcceptor,
                Sealed = this.Sealed,
                AcceptorSubKey = this.AcceptorSubKey,
            };
            var tokenBytes = wrapToken.GetBytes();

            // We have data, padding and token bytes to encrypt, copy them all into a new buffer.
            var bytes = new Memory<byte>(new byte[this.data.Length + paddingLength + tokenBytes.Length]);
            this.data.CopyTo(bytes);
            padding.CopyTo(bytes.Span[this.data.Length..]);
            var tokenOffset = this.data.Length + paddingLength;
            tokenBytes.CopyTo(bytes[tokenOffset..]);

            // Encrypt the payload DATA | PADDING | WRAP_TOKEN
            var cipherText = this.cipher.Encrypt(bytes, this.Key, KeyUsage.InitiatorSeal);

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
            this.SequenceNumber += 1; // Increment sequence number for next use
            return (cipherText[offset..], signatureBytes);
        }

        public static Memory<byte> Rotate(ReadOnlySpan<byte> bytes, int numBytes)
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
