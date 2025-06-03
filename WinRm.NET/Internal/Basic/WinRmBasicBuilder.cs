namespace WinRm.NET.Internal.Basic
{
    using WinRm.NET;
    using WinRm.NET.Internal.Kerberos;

    internal sealed class WinRmBasicBuilder
        : WinRmBuilder<IWinRmBasicSessionBuilder>, IWinRmBasicSessionBuilder
    {
        public WinRmBasicBuilder(WinRmSessionBuilder parent)
            : base(AuthType.Basic, parent)
        {
        }

        public override IWinRmSession Build(string host)
        {
            if (User == null)
            {
                throw new InvalidOperationException("User must be specified");
            }

            var securityEnvelope = new BasicSecurityEnvelope(
                Parent.Logger,
                new Credentials(User, Password!));

            return new WinRmSession(
                Parent.HttpClientFactory ?? new DefaultHttpClientFactory(),
                Parent.Logger,
                host,
                securityEnvelope);
        }
    }
}