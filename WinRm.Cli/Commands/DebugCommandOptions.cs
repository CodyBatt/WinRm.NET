﻿namespace WinRm.Cli.Commands
{
    using CommandLine;
    using WinRm.NET;

    [Verb("debug", HelpText = "Decrypt a WinRM payload given an athenticate message and password")]
    public class DebugCommandOptions
    {
        [Option('a', "authenticate_message", Required = true, HelpText = "Base64-encoded authenticate message from HTTP header")]
        public string Authenticate { get; set; } = string.Empty;

        [Option('p', "password", Required = true, HelpText = "Password used to authenticate the session")]
        public string Password { get; set; } = string.Empty;

        [Option('m', "message", Required = true, HelpText = "Base64-encoded encrypted SOAP message including encryption header and header length (everything after the content-type header)")]
        public string Message { get; set; } = string.Empty;
    }
}
