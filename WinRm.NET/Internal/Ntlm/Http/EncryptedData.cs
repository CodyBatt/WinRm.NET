namespace WinRm.NET.Internal.Ntlm.Http
{
    using System.IO;

    internal class EncryptedData
    {
        public EncryptedData(Stream stream, int dataLength)
        {
            Memory<byte> signatureLengthRaw = new byte[4];
            stream.Read(signatureLengthRaw.Span);
            var signatureLength = BitConverter.ToInt32(signatureLengthRaw.Span);
            Signature = new byte[signatureLength];
            stream.Read(Signature.Span);
            Data = new byte[dataLength];
            stream.Read(Data.Span);
        }

        public Memory<byte> Data { get; set; }

        public Memory<byte> Signature { get; set; }
    }
}