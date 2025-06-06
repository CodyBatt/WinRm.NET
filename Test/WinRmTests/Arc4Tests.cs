namespace WinRmTests
{
    using System;
    using System.Text;

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
        public void TestLargeBlockEncryption()
        {
            var key = Encoding.ASCII.GetBytes("Key");
            var encryptor = new WinRm.NET.Internal.Ntlm.NtlmEncryptor(key, key, key, key);
            var data = "Is it right? " + new String('x', 20000) + "Can you do it?";
            
            var encryptedStream = encryptor.Client.Transform(Encoding.UTF8.GetBytes(data));
            var decryptedStream = encryptor.Client.Transform(encryptedStream.Span);
            var decrypted = Encoding.UTF8.GetString(decryptedStream.Span);
            Assert.Equal(data, decrypted);
        }
    }
}
