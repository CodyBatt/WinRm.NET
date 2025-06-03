namespace WinRm.NET.Internal.Kerberos
{
    using WinRm.NET;

    // Put Kerberos-specific session parameters here
    internal sealed class WinRmKerberosBuilder
        : WinRmBuilder<IWinRmKerberosSessionBuilder>, IWinRmKerberosSessionBuilder
    {
        private string? realm;
        private HostInfo? kdcInfo;

        public WinRmKerberosBuilder(WinRmSessionBuilder parent)
            : base(AuthType.Kerberos, parent)
        {
        }

        public override IWinRmSession Build(string host)
        {
            if (User == null)
            {
                throw new InvalidOperationException("User must be specified");
            }

            if (realm == null)
            {
                throw new InvalidOperationException("Realm must be specified for Kerberos authentication.");
            }

            if (kdcInfo == null)
            {
                throw new InvalidOperationException("KDC info must be specified for Kerberos authentication.");
            }

            var securityEnvelope = new KerberosSecurityEnvelope(
                Parent.Logger,
                new Credentials(User, Password!),
                realm ?? throw new InvalidOperationException("Realm must be specified when AuthType is Kerberos."),
                kdcInfo ?? throw new InvalidOperationException("KDC information must be specified when AuthType is Kerberos."));

            return new WinRmSession(
                Parent.HttpClientFactory ?? new DefaultHttpClientFactory(),
                Parent.Logger,
                host,
                securityEnvelope);
        }

        public IWinRmKerberosSessionBuilder WithRealmName(string realm)
        {
            this.realm = realm;
            return this;
        }

        public IWinRmKerberosSessionBuilder WithKdc(string host, string address)
        {
            kdcInfo = new HostInfo
            {
                Name = host,
                Address = address,
            };
            return this;
        }
    }
}