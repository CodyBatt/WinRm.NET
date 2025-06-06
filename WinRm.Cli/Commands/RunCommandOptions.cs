namespace WinRm.Cli.Commands
{
    using CommandLine;
    using WinRm.NET;

    [Verb("run", HelpText = "Run a remote command with WinRm")]
    public class RunCommandOptions
    {
        [Option('s', "security", Required = false, HelpText = "Specify the security protocol to use: Kerberos, Ntlm or Basic", Default = AuthType.Kerberos)]
        public AuthType Authentication { get; set; }

        [Option('c', "command", Required = true, HelpText = "Specify the command to run")]
        required public string Command { get; set; }

        [Option('a', "args", Required = false, HelpText = "Specify command arguments")]
        public IEnumerable<string>? Arguments { get; set; }

        [Option('h', "host", Required = true, HelpText = "Specify the remote host target where the command will run.")]
        required public string HostName { get; set; }

        [Option('u', "user", Required = true, HelpText = "Specify the user principal that the command will run as.")]
        required public string UserName { get; set; }

        [Option('r', "realm", Required = false, HelpText = "Specify the kerberos realm.")]
        required public string RealmName { get; set; }

        // Eventually get this from stdin, this is required for both ntlm, TBD whether we will always require for kerberos
        [Option('p', "password", Required = false, HelpText = "Specifiy the user's password")]
        public string? Password { get; set; }

        [Option('v', "verbose", Required = false, Default = false, HelpText = "Display verbose logging")]
        public bool Verbose { get; set; }

        [Option('k', "kdc", Required = false, HelpText = "Sepcify KDC info as: host,ip")]
        public IEnumerable<string>? KdcInfo { get; set; }
    }
}
