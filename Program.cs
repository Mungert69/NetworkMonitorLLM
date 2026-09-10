using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NetworkMonitor.Objects.Factory;
using Microsoft.AspNetCore.Hosting;
using System;
using NetworkMonitor.Utils;

namespace NetworkMonitor.LLM
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string appFile = "appsettings.json";
            IConfigurationRoot config = new ConfigurationBuilder()
                .AddJsonFile(appFile, optional: false)
                .Build();

            var serviceConfigFiles = config.GetSection("ServiceConfigFiles")
                .Get<string[]>()?
                .Where(file => !string.IsNullOrWhiteSpace(file))
                .ToArray();

            if (serviceConfigFiles is { Length: > 0 })
            {
                CreateMultiRuntimeHost(serviceConfigFiles).Build().Run();
                return;
            }

            IHost host = CreateHostBuilder(config, args).Build();

            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(IConfigurationRoot config, string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration(builder =>
                {
                    builder.AddConfiguration(config);
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    bool useFixedPort = config.GetValue("UseFixedPort", false); // Defaults to false if missing
                    string serviceID = config.GetValue("ServiceID", "");
                    int port = config.GetValue<int>("Port", 7860); // Default to 7860

                    if (useFixedPort)
                    {
                        webBuilder.UseUrls($"http://0.0.0.0:{port}");
                    }
                    else
                    {
                        webBuilder.UseUrls($"http://0.0.0.0:{NetworkUtils.WordToPort(serviceID, 5000, 10000)}");

                    }

                    webBuilder.UseStartup<Startup>();
                });

        private static IHostBuilder CreateMultiRuntimeHost(IEnumerable<string> serviceConfigFiles) =>
            Host.CreateDefaultBuilder()
                .ConfigureServices(services =>
                {
                    services.AddSingleton(new ServiceRuntimeOptions(serviceConfigFiles.ToArray()));
                    services.AddHostedService<MultiRuntimeHostedService>();
                });
    }
}
