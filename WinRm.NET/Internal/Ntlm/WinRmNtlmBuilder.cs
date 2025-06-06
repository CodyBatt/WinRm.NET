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

        public override IWinRmSession Build(string host)
        {
            if (User == null)
            {
                throw new InvalidOperationException("User must be specified");
            }

            var securityEnvelope = new NtlmSecurityEnvelope(
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