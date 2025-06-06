namespace WinRm.Cli
{
    using CommandLine;
    using Serilog;
    using Serilog.Extensions.Logging;
    using WinRm.Cli.Commands;
    using WinRm.NET;

    internal sealed class Program
    {
        public static async Task<int> Main(string[] args)
        {
            var parser = new Parser(cfg =>
            {
                cfg.CaseInsensitiveEnumValues = true;
                cfg.HelpWriter = Console.Out;
            });

            return await parser.ParseArguments<RunCommandOptions, DebugCommandOptions>(args)
                .MapResult(
                (RunCommandOptions opts) => RunCommand(opts),
                (DebugCommandOptions opts) => DebugCommand(opts),
                errs => HandleParseError(errs));
        }

        private static async Task<int> DebugCommand(DebugCommandOptions opts)
        {
            var payload = Convert.FromBase64String(opts.Message);
            await WinRm.NET.Internal.Ntlm.SessionDebug.Debug(opts.Authenticate, opts.Password, payload);
            return 0;
        }

        private static async Task<int> RunCommand(RunCommandOptions opts)
        {
            // If using DI, register this in the container and configure it
            // with logging and httpclientfactory
            var sessionBuilder = new WinRmSessionBuilder();
            if (opts.Verbose == true)
            {
                // Set up logging
                using var log = new LoggerConfiguration()
                .WriteTo.Console()
                .MinimumLevel.Debug()
                .CreateLogger();
                var logBridge = new SerilogLoggerFactory(log);
                sessionBuilder.WithLogger(logBridge.CreateLogger("WinRm.NET"));
            }

            string kdcHost = string.Empty;
            string kdcAddress = string.Empty;
            var kdcArray = opts.KdcInfo?.ToArray();
            if (kdcArray != null && kdcArray.Length >= 2)
            {
                // If KDC info is provided, set it up
                kdcHost = kdcArray[0];
                kdcAddress = kdcArray[1];
            }

            // Create the session
            using IWinRmSession session = opts.Authentication switch
            {
                AuthType.Kerberos => sessionBuilder.WithKerberos()
                    .WithUser(opts.UserName)
                    .WithPassword(opts.Password!)
                    .WithRealmName(opts.RealmName)
                    .WithKdc(kdcHost, kdcAddress)
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

            // Run the command
            var result = await session.Run(opts.Command, opts.Arguments);

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
                    Console.WriteLine($"STDERR: {result.Error}");
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

        private static Task<int> HandleParseError(IEnumerable<Error> errs)
        {
            return Task.FromResult(1);
        }
    }
}
