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
                (RunCommandOptions opts) => opts.Execute(),
                (DebugCommandOptions opts) => opts.Execute(),
                errs => HandleParseError(errs));
        }

        private static Task<int> HandleParseError(IEnumerable<Error> errs)
        {
            return Task.FromResult(1);
        }
    }
}
