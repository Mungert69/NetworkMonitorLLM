using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Data;
using NetworkMonitor.Objects.Factory;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

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
                    // Configure Kestrel to listen on port 7860
                    webBuilder.ConfigureKestrel(serverOptions =>
                    {
                        serverOptions.ListenAnyIP(7860); // Listen on all IP addresses, port 7860
                    });

                    // Use the Startup class
                    webBuilder.UseStartup<Startup>();
                })
                .ConfigureServices((hostContext, services) =>
                {
                    // Register your Startup class's ConfigureServices method
                    var startup = new Startup(hostContext.Configuration);
                    startup.ConfigureServices(services);
                });
    }
}