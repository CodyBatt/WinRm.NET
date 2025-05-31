namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal abstract class NtlmMessage
    {
        protected NtlmMessage()
        {
        }

        protected NtlmMessage(ReadOnlyMemory<byte> messageBytes)
        {
            this.MessageBuffer = messageBytes;
            Parse();
        }

        protected ReadOnlyMemory<byte> MessageBuffer { get; set; }

        public ReadOnlyMemory<byte> GetBytes(int offset = 0, int? length = 0, bool forceBuild = false)
        {
            if (this.MessageBuffer.IsEmpty || forceBuild)
            {
                Build();
            }

            if (offset > this.MessageBuffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset is beyond the length of the message buffer.");
            }

            if (length.HasValue && length.Value > 0)
            {
                return this.MessageBuffer.Slice(offset, length.Value);
            }
            else if (offset > 0)
            {
                return this.MessageBuffer.Slice(offset);
            }

            return this.MessageBuffer;
        }

        /// <summary>
        /// Parse property values from MessageBytes.
        /// </summary>
        protected abstract void Parse();

        /// <summary>
        /// Build MessageBytes from property values.
        /// </summary>
        protected abstract void Build();
    }
}
