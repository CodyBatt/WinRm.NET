[![build test and publish](https://github.com/CodyBatt/WinRm.NET/actions/workflows/build-publish.yml/badge.svg)](https://github.com/CodyBatt/WinRm.NET/actions/workflows/build-publish.yml)

# WinRm.NET
.NET implementation of WinRM client

The driver for this project is the ability to run remote Windows commands securely from Linux. Requests run directly in .NET without any dependency on PowerShell. It should be possible to authenticate using NTLM or Kerberos from Windows or Linux without needing to be joined to a domain.

# Status
This project is a work in progress and is not suitable for production use by anyone for any purpose :P, but it's a free internet. Everything documented here is subject to change.

# Usage
Add the Nuget package `WinRm.NET` to your project.

If you are using Microsoft DI, register WinRm.NET:
```csharp
serviceCollection.AddWinRm();
```
You can also create an instance of the `WinRmSessionBuilder` class manually. `WinRmSessionBuilder` implements `IWinRm`.

Inject an `IWinRm` interface into your class and use it to create a session. The session can then be used to run commands on the remote host. Results are returned as text in the `Output` or `Error` properties of the `IWinRmResult`.

```csharp
class SomeClass(IWinRm winrm)
{
    public async Task RunAWinRmCommandUsingNtlm(string host, string username, string password, string command, IEnumerable<string>? arguments = null)
    {
        IWinRmSession winRmSession = winrm.WithNtlm()
            .WithUser(username)
            .WithPassword(password)
            .Build(hostname);

        IWinRmResult result = await session.Run(command, arguments);
        if (result.IsSuccess)
        {
           Console.WriteLine(result.Output);
        }
        else
        {
            Console.WriteLine("Error: " + result.ErrorMessage);
            Console.WriteLine(result.Error);
        }
    }
}
```

# Authentication
Basic, NTLM, and Kerberos authentication are supported. Each authentication mechanism has different requirements. Call `WithBasic()`, `WithNtlm()` or `WithKerberos()` to see options. Negotiate maybe added at a later time. Anonymous connections are not supported. NTLMv1 is not supported. Ideally, you would always use Kerberos. Support for Windows 2025 IAKerb and LocalKDC is planned so that Kerberos can be used even for Windows machines that are not joined to a domain.

# Integration Points
You can configure the HttpClient used by WinRM by providing an action delegate when registering with DI:

```csharp
serviceCollection.AddWinRm().ConfigureHttpClient(client => {
    client.Timeout = TimeSpan.FromSeconds(15);
});
```
