namespace WinRmTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using WinRm.NET.Internal.Kerberos;

    public class WrapTokenTests
    {
        [Fact]
        public void WrapToken_RotateWorks()
        {
            var bytes = new byte[] { 1,2,3,4,5,6,7,8 };
            var expected = new byte[] { 6,7,8,1,2,3,4,5 };
            var rotated = WinRm.NET.Internal.Kerberos.Gss.Rotate(bytes, 3);
            Assert.Equal(expected, rotated.ToArray());
        }

        [Fact]
        public void WrapToken_UnRotateWorks()
        {
            var bytes = new byte[] { 6,7,8,1,2,3,4,5 };
            var expected = new byte[] { 1,2,3,4,5,6,7,8 };
            var rotated = WinRm.NET.Internal.Kerberos.Gss.UnRotate(bytes, 3);
            Assert.Equal(expected, rotated.ToArray());
        }

        [Fact]
        public void WrapUnWrapWorks()
        {
            Random rnd = new Random(10);
            byte[] b = new byte[5 * 1024]; // convert kb to byte
            rnd.NextBytes(b);
            var rotated = Gss.Rotate(b, 28);
            var unrotated = Gss.UnRotate(rotated.Span, 28);
            Assert.Equal(b, unrotated.ToArray());
        }
    }
}
