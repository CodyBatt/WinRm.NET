namespace WinRm.NET.Internal.Kerberos
{
    using WinRm.NET;

    // Put Kerberos-specific session parameters here
    internal sealed class WinRmKerberosBuilder
        : WinRmBuilder<IWinRmKerberosSessionBuilder>, IWinRmKerberosSessionBuilder
    {
        private string? realm;
        private string? kdc;
        private string? spn;
        private string? dns;

        public WinRmKerberosBuilder(WinRmSessionBuilder parent)
            : base(AuthType.Kerberos, parent)
        {
        }

        public override IWinRmSession Build(string host, int? port = null)
        {
            if (User == null)
            {
                throw new InvalidOperationException("User must be specified");
            }

            var securityEnvelope = new KerberosSecurityEnvelope(
                Parent.Logger,
                new Credentials(User, Password!),
                realm,
                kdc,
                spn,
                dns);

            if (this.Parent.LoggerFactory != null)
            {
                securityEnvelope.SetLoggerFactory(this.Parent.LoggerFactory);
            }

            return new WinRmSession(host,
                securityEnvelope,
                Parent.HttpClientFactory ?? new DefaultHttpClientFactory(),
                Parent.Logger,
                port);
        }

        public IWinRmKerberosSessionBuilder WithRealmName(string? realm)
        {
            this.realm = realm;
            return this;
        }

        public IWinRmKerberosSessionBuilder WithKdc(string? address)
        {
            this.kdc = address;
            return this;
        }

        public IWinRmKerberosSessionBuilder WithSpn(string? spn)
        {
            this.spn = spn;
            return this;
        }

        public IWinRmKerberosSessionBuilder WithDns(string? dns)
        {
            this.dns = dns;
            return this;
        }
    }
}