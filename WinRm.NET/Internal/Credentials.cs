namespace WinRm.NET.Internal
{
    // Will this be sufficient for Kerberos? We might need something more here, but I'm not sure
    internal sealed class Credentials(string user, string password = "")
    {
        public Credentials(string user, string domain, string password)
            : this(user, password)
        {
            Domain = domain;
        }

        public string User { get; set; } = user;

        public string Password { get; set; } = password;

        public string Domain { get; set; } = string.Empty;
    }
}
