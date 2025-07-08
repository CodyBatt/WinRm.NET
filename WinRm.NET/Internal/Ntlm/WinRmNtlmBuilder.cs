namespace WinRm.NET.Internal.Ntlm
{
    using WinRm.NET;

    internal sealed class WinRmNtlmBuilder
        : WinRmBuilder<IWinRmNtlmSessionBuilder>, IWinRmNtlmSessionBuilder
    {
        public WinRmNtlmBuilder(WinRmSessionBuilder parent)
            : base(AuthType.Basic, parent)
        {
        }

        public override IWinRmSession Build(string host, int? port = null)
        {
            if (User == null)
            {
                throw new InvalidOperationException("User must be specified");
            }

            var securityEnvelope = new NtlmSecurityEnvelope(
                Parent.Logger,
                new Credentials(User, Password!));

            return new WinRmSession(
                host,
                securityEnvelope,
                Parent.HttpClientFactory ?? new DefaultHttpClientFactory(),
                Parent.Logger,
                port);
        }
    }
}