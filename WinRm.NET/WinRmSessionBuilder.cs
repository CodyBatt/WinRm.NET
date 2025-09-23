namespace WinRm.NET
{
    using System.Net.Http;
    using Microsoft.Extensions.Logging;
    using WinRm.NET.Internal.Basic;
    using WinRm.NET.Internal.Kerberos;
    using WinRm.NET.Internal.Ntlm;

    public sealed class WinRmSessionBuilder : IWinRm, IWinRmConfig
    {
        internal ILoggerFactory? LoggerFactory { get; private set; }

        internal ILogger? Logger => LazyLogger.Value;

        internal IHttpClientFactory? HttpClientFactory { get; private set; }

        private Lazy<ILogger?> LazyLogger => new Lazy<ILogger?>(LoggerFactory?.CreateLogger("WinRm.NET") ?? null);

        // Choose one of the following authentication types
        public IWinRmKerberosSessionBuilder WithKerberos() => new WinRmKerberosBuilder(this);

        public IWinRmNtlmSessionBuilder WithNtlm() => new WinRmNtlmBuilder(this);

        public IWinRmBasicSessionBuilder WithBasic() => new WinRmBasicBuilder(this);

        // Integration points
        public IWinRm WithLogger(ILoggerFactory logger)
        {
            LoggerFactory = logger;
            return this;
        }

        public IWinRm WithHttpClientFactory(IHttpClientFactory httpClientFactory)
        {
            HttpClientFactory = httpClientFactory;
            return this;
        }
    }
}
