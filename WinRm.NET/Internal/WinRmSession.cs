namespace WinRm.NET.Internal
{
    using Microsoft.Extensions.Logging;

    internal sealed class WinRmSession
            : IWinRmSession
    {
        private bool disposedValue;

        public WinRmSession(IHttpClientFactory clientFactory,
        ILogger? logger,
        string host,
        ISecurityEnvelope securityEnvelope)
        {
            HttpClientFactory = clientFactory;
            Logger = logger;
            Host = host;
            SecurityEnvelope = securityEnvelope;
        }

        internal IHttpClientFactory HttpClientFactory { get; private set; }

        internal ILogger? Logger { get; private set; }

        internal string Host { get; private set; }

        internal ISecurityEnvelope SecurityEnvelope { get; private set; }

        public async Task<IWinRmResult> Run(string command, IEnumerable<string>? arguments = null)
        {
            Log.RunningCommand(Logger, SecurityEnvelope.AuthType, command, Host, SecurityEnvelope.User);
            try
            {
                var protocol = new WinRmProtocol(this, SecurityEnvelope);
                await SecurityEnvelope.Initialize(protocol);

                // Step 1: Open a shell on the remote host
                var shellId = await protocol.OpenShell();
                Log.OpenedShell(Logger, shellId);

                try
                {
                    // Step 2: Execute the command in the remote shell
                    var commandId = await protocol.ExecuteCommand(shellId, command, arguments);
                    Log.StartedCommand(Logger, shellId, commandId);

                    try
                    {
                        // Step 3: Get the result of the command execution
                        var result = await protocol.GetCommandResult(shellId, commandId);
                        Log.GotCommandResult(Logger, shellId, commandId, result.StatusCode);

                        return new WinRmResult
                        {
                            IsSuccess = true,
                            Output = result.StdOutput,
                            Error = result.StdError,
                        };
                    }
                    finally
                    {
                        // Step 4: Cleanup the command (signal to exit if it timed out or hung)
                        await protocol.TerminateOperation(shellId, commandId);
                        Log.TerminatedCommand(Logger, shellId, commandId);
                    }
                }
                finally
                {
                    // Step 5: Close the shell
                    await protocol.CloseShell(shellId);
                    Log.ClosedShell(Logger, shellId);
                }
            }
            catch (Exception ex)
            {
                return new WinRmResult
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message,
                };
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // If this is our default factory, we need to clean it up
                    if (HttpClientFactory is DefaultHttpClientFactory factory)
                    {
                        factory.Dispose();
                    }
                }

                disposedValue = true;
            }
        }
    }
}