namespace WinRm.NET.Internal
{
    using WinRm.NET;

    // Common implementation for WinRm session builders
    internal abstract class WinRmBuilder<TReturnType>(AuthType authType, WinRmSessionBuilder parent)
        : IWinRmSessionBuilder<TReturnType>
        where TReturnType : class, IWinRmSessionBuilder<TReturnType>
    {
        protected string? User { get; private set; }

        protected string? Password { get; private set; }

        protected AuthType AuthType => authType;

        protected WinRmSessionBuilder Parent => parent;

        public abstract IWinRmSession Build(string host, int? port = null);

        public TReturnType WithPassword(string password)
        {
            this.Password = password;
            return (this as TReturnType)!;
        }

        public TReturnType WithUser(string user)
        {
            this.User = user;
            return (this as TReturnType)!;
        }
    }
}