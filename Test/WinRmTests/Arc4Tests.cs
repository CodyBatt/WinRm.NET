namespace WinRmTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public class Arc4Tests
    {
        private static readonly byte[] CIPHER_PLAINTEXT = new byte[]
        {
            0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3
        };

        [Fact]
        public void TestArc4Encryption()
        { 
            // Arrange
            var key = Encoding.ASCII.GetBytes("Key");
            var arc4 = new WinRm.NET.Internal.Crypto.Arc4(key);

            var expectedOutput = CIPHER_PLAINTEXT;

            // Act
            var input = Encoding.ASCII.GetBytes("Plaintext");
            var output = new byte[input.Length];
            arc4.ProcessBytes(input, output);
            // Assert
            Assert.Equal(expectedOutput, output);
        }

        [Fact]
        public void TestArc4EncryptionReentrance()
        { 
            // Arrange
            var key = Encoding.ASCII.GetBytes("Key");
            var arc4 = new WinRm.NET.Internal.Crypto.Arc4(key);

            var expectedOutput = CIPHER_PLAINTEXT;

            // Act
            var input1 = Encoding.ASCII.GetBytes("Plain");
            var output1 = new byte[input1.Length];
            arc4.ProcessBytes(input1, output1);

            var input2 = Encoding.ASCII.GetBytes("text");
            var output2 = new byte[input2.Length];
            arc4.ProcessBytes(input2, output2);

            // Assert
            var combined = new byte[output1.Length + output2.Length];
            output1.CopyTo(combined, 0);
            output2.CopyTo(combined, output1.Length);
            Assert.Equal(expectedOutput, combined);
        }

        [Fact]
        public void TestStreamEncryptor()
        {
            var encryptor = new WinRm.NET.Internal.Ntlm.NtlmEncryptor(Encoding.ASCII.GetBytes("Key"));
            var input = new MemoryStream(Encoding.ASCII.GetBytes("Plaintext"));
            var encryptedStream = encryptor.Encrypt(input);
            var decryptedStream = encryptor.Decrypt(encryptedStream);
            decryptedStream.Position = 0;
            Assert.Equal("Plaintext", new StreamReader(decryptedStream).ReadToEnd());

            encryptedStream = encryptor.Encrypt(new MemoryStream(Encoding.ASCII.GetBytes("Ciphertext")));
            decryptedStream = encryptor.Decrypt(encryptedStream);
            decryptedStream.Position = 0;
            Assert.Equal("Ciphertext", new StreamReader(decryptedStream).ReadToEnd());
        }

        [Fact]
        public void TestLargeBlockEncryption()
        {
            var data = new String('x', 10000);
            var encryptor = new WinRm.NET.Internal.Ntlm.NtlmEncryptor(Encoding.ASCII.GetBytes("Key"));
            using var input = new MemoryStream();
            using var streamWriter = new StreamWriter(input) { AutoFlush = true };
            streamWriter.Write(data);
            var encryptedStream = encryptor.Encrypt(input);
            var decryptedStream = encryptor.Decrypt(encryptedStream);
            decryptedStream.Position = 0;
            using var reader = new StreamReader(decryptedStream);
            var s = reader.ReadToEnd();
            Assert.Equal(data, s);
        }
    }
}
