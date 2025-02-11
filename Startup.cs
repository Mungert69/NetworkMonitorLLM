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
            var openAiService = new OpenAIService(new OpenAIOptions()
            {
                ApiKey = Configuration["OpenAIApiKey"] ?? "Api Key Missing"
            });
            services.AddSingleton(
                    openAiService
            );
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
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IHostApplicationLifetime appLifetime)
        {

            appLifetime.ApplicationStopping.Register(() =>
            {
                _cancellationTokenSource.Cancel();
            });

        }
    }
}
