namespace WinRm.Cli.Commands
{
    using CommandLine;
    using Serilog;
    using Serilog.Extensions.Logging;
    using WinRm.NET;

    [Verb("run", HelpText = "Run a remote command with WinRm")]
    public class RunCommandOptions : ICliCommand
    {
        [Option('s', "security", Required = false, HelpText = "Specify the security protocol to use: Kerberos, Ntlm or Basic", Default = AuthType.Kerberos)]
        public AuthType Authentication { get; set; }

        [Option('c', "command", Required = true, HelpText = "Specify the command to run, this can be a UCS2-LE Base64 encoded powershell script if -e is set.")]
        required public string Command { get; set; }

        [Option('e', "encoded", Required = false, HelpText = "Indicates that the command is intended to be passed as powershell -EncodedCommand parameter. (UCS-2LE Base64 Encoded)", Default = false)]
        required public bool Encoded { get; set; } = false;

        [Option('a', "args", Required = false, HelpText = "Specify command arguments")]
        public IEnumerable<string>? Arguments { get; set; }

        [Option('h', "host", Required = true, HelpText = "Specify the remote host target where the command will run.")]
        required public string HostName { get; set; }

        [Option('u', "user", Required = true, HelpText = "Specify the user principal that the command will run as.")]
        required public string UserName { get; set; }

        // Eventually get this from stdin, this is required for both ntlm, TBD whether we will always require for kerberos
        [Option('p', "password", Required = false, HelpText = "Specifiy the user's password")]
        public string? Password { get; set; }

        [Option('v', "verbose", Required = false, Default = false, HelpText = "Display verbose logging")]
        public bool Verbose { get; set; }

        [Option('k', "kdc", Required = false, HelpText = "Specify KDC address")]
        public string? Kdc { get; set; }

        [Option('r', "realm", Required = false, HelpText = "Specify the Kerberos realm.")]
        required public string RealmName { get; set; }

        [Option('S', "spn", Required = false, HelpText = "Specify the Kerberos SPN of the host target.")]
        public string? Spn { get; set; }

        [Option('D', "dns", Required = false, HelpText = "Specify the DNS server to use.")]
        public string? DnsServer { get; set; }

        public async Task<int> Execute()
        {
            RunCommandOptions opts = this;

            // If using DI, register this in the container and configure it
            // with logging and httpclientfactory
            var sessionBuilder = new WinRmSessionBuilder();
            if (opts.Verbose == true)
            {
                // Set up logging
                Log.Logger = new LoggerConfiguration()
                    .WriteTo.Console()
                    .MinimumLevel.Debug()
                    .CreateLogger();
                sessionBuilder.WithLogger(new SerilogLoggerFactory(Log.Logger));
            }

            // Create the session
            using IWinRmSession session = opts.Authentication switch
            {
                AuthType.Kerberos => sessionBuilder.WithKerberos()
                    .WithUser(opts.UserName)
                    .WithPassword(opts.Password!)
                    .WithRealmName(opts.RealmName)
                    .WithKdc(opts.Kdc)
                    .WithSpn(opts.Spn)
                    .WithDns(opts.DnsServer)
                    .Build(opts.HostName),
                AuthType.Ntlm => sessionBuilder.WithNtlm()
                    .WithUser(opts.UserName)
                    .WithPassword(opts.Password!)
                    .Build(opts.HostName),
                AuthType.Basic => sessionBuilder.WithBasic()
                    .WithUser(opts.UserName)
                    .WithPassword(opts.Password!)
                    .Build(opts.HostName),
                _ => throw new NotImplementedException($"Authentication mode '{opts.Authentication}' is not implemented.")
            };

            IWinRmResult result;
            if (opts.Encoded)
            {
                var encodedCommand = opts.Command;
                var command = "powershell.exe";
                var args = new string[]
                {
                    "-EncodedCommand",
                    encodedCommand,
                };
                Serilog.Log.Debug("Running encoded command: ====");
                Serilog.Log.Debug(System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String(encodedCommand)));
                Serilog.Log.Debug("====");
                result = await session.Run(command, args);
            }
            else
            {
                result = await session.Run(opts.Command, opts.Arguments?.ToArray());
            }

            // Show results
            if (result.IsSuccess)
            {
                if (!string.IsNullOrEmpty(result.Output))
                {
                    Console.WriteLine(result.Output);
                }
                else
                {
                    Console.WriteLine($"Command '{opts.Command}' executed successfully and returned no output.");
                }

                if (!string.IsNullOrEmpty(result.Error))
                {
                    var color = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{result.Error}");
                    Console.ForegroundColor = color;
                }
            }
            else
            {
                var color = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{result.ErrorMessage}");
                Console.ForegroundColor = color;
            }

            return 0;
        }
    }
}
