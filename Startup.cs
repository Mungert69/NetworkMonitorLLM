using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.LLM.Services.Cache;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Coordinator;
using NetworkMonitor.Utils;
using NetworkMonitor.Utils.Helpers;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Managers;
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using HostInitActions;

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
                // Use logging configuration from appsettings-*.json
                builder.AddConfiguration(Configuration.GetSection("Logging"));
                builder.AddSimpleConsole(options =>
                {
                    options.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
                    options.IncludeScopes = true;
                });
            });




            services.AddSingleton(provider =>
            {
                var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
                var httpLogger = loggerFactory.CreateLogger<OpenAILoggingHandler>();
                var systemParamsHelper = provider.GetRequiredService<ISystemParamsHelper>();
                var mlParams = systemParamsHelper.GetMLParams();
                var useHF = mlParams.LlmUseHF;
                StringUtils.ConfigureToolCallId(mlParams.LlmToolCallIdPrefix, mlParams.LlmToolCallIdLength);
                OpenAIOptions openAIOptions;
                if (useHF)
                {
                    string? baseDomain = null;
                    if (!string.IsNullOrWhiteSpace(mlParams.LlmHFUrl)
                        && Uri.TryCreate(mlParams.LlmHFUrl, UriKind.Absolute, out var hfUri))
                    {
                        baseDomain = hfUri.GetLeftPart(UriPartial.Authority);
                    }
                    openAIOptions = new OpenAIOptions
                    {
                        ApiKey = mlParams.LlmHFKey,
                    };
                    if (!string.IsNullOrWhiteSpace(baseDomain))
                    {
                        openAIOptions.BaseDomain = baseDomain;
                    }
                }
                else
                {
                    openAIOptions = new OpenAIOptions
                    {
                        ApiKey = mlParams.OpenAIApiKey,
                    };
                    if (!string.IsNullOrWhiteSpace(mlParams.LlmOpenAIUrl)
                        && Uri.TryCreate(mlParams.LlmOpenAIUrl, UriKind.Absolute, out var openAiUri))
                    {
                        openAIOptions.BaseDomain = openAiUri.GetLeftPart(UriPartial.Authority);
                    }
                }

                // Inner (native) handler
#if NETSTANDARD2_0
    HttpMessageHandler inner = new HttpClientHandler
    {
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
    };
#else
                HttpMessageHandler inner = new SocketsHttpHandler
                {
                    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(5)
                };
#endif

                // URL rewriter -> logger -> inner
                var rewriter = new NovitaPathFixHandler { InnerHandler = inner };
                var logging = new OpenAILoggingHandler(httpLogger) { InnerHandler = rewriter };

                var httpClient = new HttpClient(logging) { Timeout = TimeSpan.FromSeconds(120) };

                // IMPORTANT: when passing HttpClient, wrap options as IOptions
                var svc = new OpenAIService(Options.Create(openAIOptions), httpClient);

                loggerFactory.CreateLogger("OpenAI.Bootstrap")
                    .LogInformation("OpenAI BaseDomain={BaseDomain}", openAIOptions.BaseDomain);

                return svc;
            });

            services.AddSingleton<IAudioGenerator, AudioGenerator>();
            services.AddSingleton<IRabbitListener, RabbitListener>();
            services.AddSingleton<IRabbitRepo, RabbitRepo>();
            services.AddSingleton<IFileRepo, FileRepo>();
            services.AddSingleton<ISystemParamsHelper, SystemParamsHelper>();
            services.AddTransient<ILLMResponseProcessor, LLMResponseProcessor>();
            services.AddSingleton<ILLMService, LLMService>();
            services.AddSingleton<ILLMFactory, LLMFactory>();
            services.AddSingleton<IHistoryStorage, RedisHistoryStorage>();
            services.AddSingleton(_cancellationTokenSource);
            services.Configure<HostOptions>(s => s.ShutdownTimeout = TimeSpan.FromMinutes(5));
            services.AddSingleton<ICpuUsageMonitor, CpuUsageMonitor>();
            services.AddSingleton<IQueryCoordinator, QueryCoordinator>();
            services.AddSingleton<IFunctionDefinitionRegistry, FunctionDefinitionRegistry>();
            services.AddSingleton<IToolsBuilderFactory, ToolsBuilderFactory>();
            
            // Configure Remote Cache Services
            // Register Remote Cache Service Factory
            services.AddSingleton<IRemoteCacheServiceFactory, RemoteCacheServiceFactory>();
            
            // Register System Prompt Writer
            services.AddSingleton<ISystemPromptWriter, SystemPromptWriter>();
            
            services.AddSingleton<MLParams>(sp =>
            {
                var systemParamsHelper = sp.GetRequiredService<ISystemParamsHelper>();
                return systemParamsHelper.GetMLParams();
            });
            services.AddSingleton<SystemParams>(sp =>
           {
               var systemParamsHelper = sp.GetRequiredService<ISystemParamsHelper>();
               return systemParamsHelper.GetSystemParams();
           });

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
                       var jsonBytes = System.Text.Encoding.UTF8.GetBytes("{\"status\": \"healthy\"}");
                       await context.Response.BodyWriter.WriteAsync(jsonBytes);
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
