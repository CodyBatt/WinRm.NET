namespace WinRm.NET.Internal.Ntlm
{
    using System;

    [Flags]
    public enum AvFlags
    {
        CONSTRAINED = 0x01,
        INTEGRITY = 0x02,
        UNTRUSTED_SPN_SOURCE = 0x04,
    }
}
