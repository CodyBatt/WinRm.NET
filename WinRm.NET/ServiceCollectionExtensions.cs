namespace WinRm.NET
{
    using System;
    using System.ComponentModel.Design;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection RegisterWinRm(this IServiceCollection services, Action<IServiceProvider, IWinRmConfig>? configure = null)
        {
            services.AddSingleton<IWinRm>(sp =>
            {
                var builder = new WinRmSessionBuilder();

                // If a custom logger is provided, use it
                if (sp.TryGetService(out ILoggerFactory? loggerFactory))
                {
                    builder.WithLogger(loggerFactory!);
                }

                // If a custom HttpClientFactory is provided, use it
                if (sp.TryGetService(out IHttpClientFactory? httpClientFactory))
                {
                    builder.WithHttpClientFactory(httpClientFactory!);
                }

                // Allow additional configuration via the action delegate
                configure?.Invoke(sp, builder);
                return builder;
            });

            return services;
        }

        private static bool TryGetService<T>(this IServiceProvider provider, out T? service)
            where T : class
        {
            service = provider.GetService<T>();
            return service != null;
        }
    }
}
