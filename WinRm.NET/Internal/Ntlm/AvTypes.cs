namespace WinRm.NET.Internal.Ntlm
{
    internal enum AvPairTypes
    {
         MsvAvEOL = 0x0000,
         MsvAvNbComputerName = 0x0001,
         MsvAvNbDomainName = 0x0002,
         MsvAvDnsComputerName = 0x0003,
         MsvAvDnsDomainName = 0x0004,
         MsvAvDnsTreeName = 0x0005,
         MsvAvFlags = 0x0006,
         MsvAvTimestamp = 0x0007,
         MsvAvSingleHost = 0x0008,
         MsvAvTargetName = 0x0009,
         MsvAvChannelBindings = 0x000A,
    }
}
