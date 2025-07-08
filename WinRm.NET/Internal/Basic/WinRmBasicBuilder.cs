namespace WinRm.NET.Internal.Basic
{
    using WinRm.NET;

    internal sealed class WinRmBasicBuilder
        : WinRmBuilder<IWinRmBasicSessionBuilder>, IWinRmBasicSessionBuilder
    {
        public WinRmBasicBuilder(WinRmSessionBuilder parent)
            : base(AuthType.Basic, parent)
        {
        }

        public override IWinRmSession Build(string host, int? port = null)
        {
            if (User == null)
            {
                throw new InvalidOperationException("User must be specified");
            }

            var securityEnvelope = new BasicSecurityEnvelope(
                Parent.Logger,
                new Credentials(User, Password!));

            return new WinRmSession(host,
                securityEnvelope,
                Parent.HttpClientFactory ?? new DefaultHttpClientFactory(),
                Parent.Logger,
                port);
        }
    }
}