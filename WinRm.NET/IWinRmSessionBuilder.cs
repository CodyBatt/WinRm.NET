namespace WinRm.NET
{
    public interface IWinRmSessionBuilder
    {
        IWinRmSession Build(string host, int? port = null);
    }

    public interface IWinRmSessionBuilder<T>
        : IWinRmSessionBuilder
    {
        T WithUser(string user);

        T WithPassword(string password);
    }

    public interface IWinRmBasicSessionBuilder
        : IWinRmSessionBuilder<IWinRmBasicSessionBuilder>
    {
    }

    public interface IWinRmNtlmSessionBuilder
        : IWinRmSessionBuilder<IWinRmNtlmSessionBuilder>
    {
    }

    public interface IWinRmKerberosSessionBuilder
        : IWinRmSessionBuilder<IWinRmKerberosSessionBuilder>
    {
        IWinRmKerberosSessionBuilder WithRealmName(string? realm);

        IWinRmKerberosSessionBuilder WithKdc(string? address);

        IWinRmKerberosSessionBuilder WithSpn(string? spn);

        IWinRmKerberosSessionBuilder WithDns(string? dns);
    }
}
