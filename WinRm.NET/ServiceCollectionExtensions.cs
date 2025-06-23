namespace WinRm.NET
{
    using System;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection RegisterWinRm(this IServiceCollection services, Action<IWinRmConfig>? configure = null)
        {
            services.AddSingleton<IWinRm>(provider =>
            {
                var builder = new WinRmSessionBuilder();
                var defaultFactory = provider.GetService<IHttpClientFactory>();
                var defaultLogger = provider.GetService<ILogger>();
                builder.WithHttpClientFactory(defaultFactory);
                builder.WithLogger(defaultLogger);
                configure?.Invoke(builder);
                return builder;
            });

            return services;
        }
    }
}
