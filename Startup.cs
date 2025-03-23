using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Data;
using NetworkMonitor.Objects;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Objects.Repository;
using HostInitActions;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.ServiceMessage;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
namespace NetworkMonitor.LLM
{
    public class Startup
    {
        private readonly CancellationTokenSource _cancellationTokenSource;
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

  private readonly string _htmlContent = @"
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Free Network Monitor Assistant</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                    text-align: center;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 20px 0;
                }
                header img {
                    width: 200px;
                }
                main {
                    padding: 20px;
                }
                .content {
                    max-width: 800px;
                    margin: 0 auto;
                    text-align: left;
                }
                h1 {
                    color: #333;
                }
                p {
                    font-size: 18px;
                    color: #666;
                }
                .highlight {
                    color: #1e88e5;
                    font-weight: bold;
                }
                footer {
                    background-color: #333;
                    color: white;
                    padding: 10px;
                }
            </style>
        </head>
        <body>

        <header>
            <img src='https://freenetworkmonitor.click/img/logo.jpg' alt='Free Network Monitor Logo'>
            <h1>Welcome to the Free Network Monitor Assistant</h1>
        </header>

        <main>
            <div class='content'>
                <p>The Free Network Monitor Assistant is powered by a robust LLM backend that helps monitor your network services and website performance. This assistant is a key feature of the <a href='https://freenetworkmonitor.click' target='_blank' class='highlight'>Free Network Monitor</a> platform, offering comprehensive monitoring solutions.</p>

                <p>To access the assistant, simply go to <a href='https://freenetworkmonitor.click' target='_blank'>Free Network Monitor</a> and click on the assistant icon located at the bottom right of the main or dashboard pages.</p>

                <h2>What can the Assistant do?</h2>
                <p>The assistant can help you:</p>
                <ul>
                    <li>Monitor network services and website performance</li>
                    <li>Check quantum readiness of your network</li>
                    <li>Alert you about service failures through email notifications</li>
                    <li>Provide real-time monitoring insights for a wide range of services including HTTP, ICMP, DNS, and SMTP</li>
                </ul>

                <p>Stay ahead of the curve with the Free Network Monitor Assistant and keep your services online 24/7!</p>
            </div>
        </main>

        <footer>
            <p>&copy; 2025 Free Network Monitor. All rights reserved.</p>
        </footer>

        </body>
        </html>";
    
        public Startup(IConfiguration configuration)
        {
            _cancellationTokenSource = new CancellationTokenSource();
            Configuration = configuration;
        }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

        public IConfiguration Configuration { get; }
        private IServiceCollection _services;
        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            _services = services;
            services.AddLogging(builder =>
                          {
                              builder.AddSimpleConsole(options =>
                        {
                            options.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
                            options.IncludeScopes = true;
                        });

                          });

            services.AddSingleton(provider =>
             {
                 var systemParamsHelper = provider.GetRequiredService<ISystemParamsHelper>();
                 string openAIApiKey = "";
                 if (systemParamsHelper != null)
                 {
                     openAIApiKey = systemParamsHelper.GetMLParams().OpenAIApiKey;
                 }
                 if (string.IsNullOrEmpty(openAIApiKey)) openAIApiKey = "Api Key Missing";

                 var openAIOptions = new OpenAIOptions()
                 {
                     ApiKey = openAIApiKey
                 };

                 return new OpenAIService(openAIOptions);
             });

            services.AddSingleton<IAudioGenerator, AudioGenerator>();
            services.AddSingleton<IRabbitListener, RabbitListener>();
            services.AddSingleton<IRabbitRepo, RabbitRepo>();
            services.AddSingleton<IFileRepo, FileRepo>();
            services.AddSingleton<ISystemParamsHelper, SystemParamsHelper>();
            services.AddTransient<ILLMResponseProcessor, LLMResponseProcessor>();
            services.AddSingleton<ILLMService, LLMService>();
            services.AddSingleton<ILLMFactory, LLMFactory>();
            services.AddSingleton<IHistoryStorage, FileSystemHistoryStorage>();
            services.AddSingleton(_cancellationTokenSource);
            services.Configure<HostOptions>(s => s.ShutdownTimeout = TimeSpan.FromMinutes(5));
            services.AddSingleton<ICpuUsageMonitor, CpuUsageMonitor>();
            services.AddSingleton<IQueryCoordinator, QueryCoordinator>();


            services.AddHostedService<CpuUsageMonitor>();

            services.AddAsyncServiceInitialization()
                .AddInitAction<IRabbitRepo>(async (rabbitRepo) =>
                    {
                        await rabbitRepo.ConnectAndSetUp();
                    })
                    .AddInitAction<IRabbitListener>(async (rabbitListener) =>
                    {
                        await rabbitListener.Setup();

                    })
                    .AddInitAction<ILLMService>(async (llmService) =>
                    {
                        await llmService.Init();

                    });

        }
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IHostApplicationLifetime appLifetime)
        {
            app.UseRouting();

            bool useFixedPort = Configuration.GetValue<bool>("UseFixedPort", false); // Defaults to false if missing

            if (useFixedPort)
            {
                app.UseEndpoints(endpoints =>
               {
                   endpoints.MapGet("/health", async context =>
                   {
                       context.Response.ContentType = "application/json";
                       await context.Response.WriteAsync("{\"status\": \"healthy\"}");
                   });
                    endpoints.MapGet("/", async context =>
                {
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(_htmlContent);
                });
               });

            }


            appLifetime.ApplicationStopping.Register(() =>
            {
                _cancellationTokenSource.Cancel();
            });
        }

    }
}
