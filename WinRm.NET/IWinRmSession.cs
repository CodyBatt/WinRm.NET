namespace WinRm.NET
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IWinRmSession : IDisposable
    {
        Task<IWinRmResult> Run(string command, IEnumerable<string>? arguments = null);
    }
}
