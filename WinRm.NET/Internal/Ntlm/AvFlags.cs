namespace WinRm.NET.Internal.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    [Flags]
    public enum AvFlags
    {
        CONSTRAINED = 0x01,
        INTEGRITY = 0x02,
        UNTRUSTED_SPN_SOURCE = 0x04,
    }
}
