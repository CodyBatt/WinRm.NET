namespace WinRm.NET.Internal.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal class Arc4
    {
        private static readonly int KeyStreamSize = 256;

        private int x;
        private int y;
        private byte[] workingKey;
        private byte[] state;

        public Arc4(ReadOnlyMemory<byte> key)
        {
            if (state == null)
            {
                state = new byte[KeyStreamSize];
            }

            workingKey = key.ToArray();
            SetKey(workingKey);
        }

        public virtual void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (output.Length < input.Length)
            {
                throw new InvalidOperationException("Output buffer is too small!");
            }

            for (int i = 0; i < input.Length; i++)
            {
                x = (x + 1) & 0xff;
                y = (state[x] + y) & 0xff;

                byte sx = state[x];
                byte sy = state[y];

                state[x] = sy;
                state[y] = sx;

                output[i] = (byte)(input[i] ^ state[(sx + sy) & 0xff]);
            }
        }

        private void SetKey(byte[] keyBytes)
        {
            workingKey = keyBytes;

            x = 0;
            y = 0;

            for (int i = 0; i < KeyStreamSize; i++)
            {
                state[i] = (byte)i;
            }

            int i1 = 0;
            int i2 = 0;

            for (int i = 0; i < KeyStreamSize; i++)
            {
                i2 = ((keyBytes[i1] & 0xff) + state[i] + i2) & 0xff;

                byte tmp = state[i];
                state[i] = state[i2];
                state[i2] = tmp;
                i1 = (i1 + 1) % keyBytes.Length;
            }
        }
    }
}
