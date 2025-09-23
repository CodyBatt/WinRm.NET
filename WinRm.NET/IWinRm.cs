namespace WinRm.NET
{
    using System.Net.Http;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Main entry point for creating a WinRm session.
    /// </summary>
    public interface IWinRm
    {
        /// <summary>
        /// Creates a new session with basic authentication. This is not
        /// secure! Your credentials and all traffic are exposed. This
        /// is only for development and testing purposes. If you use this
        /// in production, you will be hacked.
        /// </summary>
        /// <returns>IWinRmSessionBuilder</returns>
        IWinRmBasicSessionBuilder WithBasic();

        /// <summary>
        /// Creates a new session with Kerberos authentication. This is
        /// the most secure way to use WinRm.
        /// </summary>
        /// <returns>IWInRmSessionBuilder</returns>
        IWinRmKerberosSessionBuilder WithKerberos();

        /// <summary>
        /// Creates a new session with NTLM authentication.
        /// </summary>
        /// <returns>IWInRmSessionBuilder</returns>
        IWinRmNtlmSessionBuilder WithNtlm();
    }

    public interface IWinRmConfig
    {
        /// <summary>
        /// Allows consumers to inject their own IHttpClientFactory
        /// from whatever DI container is in use. By default,
        /// an internal HttpClientFactory is used.
        /// </summary>
        /// <param name="httpClientFactory">An HttpClientFactory</param>
        /// <returns>IWinRm</returns>
        IWinRm WithHttpClientFactory(IHttpClientFactory httpClientFactory);

        /// <summary>
        /// Allows consumers to inject their own ILoggerFactory instance derived
        /// from whatever logging framework is in use.
        /// </summary>
        /// <param name="logger">An ILoggerFactory instance</param>
        /// <returns>IWinRm</returns>
        IWinRm WithLogger(ILoggerFactory logger);
    }
}