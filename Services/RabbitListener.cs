using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Data.Services;
using System.Collections.Generic;
using System;
using System.Text;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using NetworkMonitor.Utils;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Repository;
using System.Net;
using Microsoft.EntityFrameworkCore.Diagnostics;
namespace NetworkMonitor.LLM.Services;

public interface IRabbitListener
{

    Task<ResultObj> StartSession(LLMServiceObj? llmServiceObj);
    Task<ResultObj> UserInput(LLMServiceObj? llmServiceObj);
    Task Shutdown();
    Task<ResultObj> Setup();


}

public class RabbitListener : RabbitListenerBase, IRabbitListener
{
    protected ILLMService _llmService;
    private string _serviceID = "monitor";
       private readonly IQueryCoordinator _queryCoordinator;

    public RabbitListener(ILLMService llmService, ILogger<RabbitListenerBase> logger, ISystemParamsHelper systemParamsHelper, IQueryCoordinator queryCoordinator) : base(logger, DeriveSystemUrl(systemParamsHelper))
    {

        _llmService = llmService;
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID ?? "monitor";
        _queryCoordinator=queryCoordinator;
        Setup();
    }

    private static SystemUrl DeriveSystemUrl(ISystemParamsHelper systemParamsHelper)
    {
        return systemParamsHelper.GetSystemParams().ThisSystemUrl;
    }
    protected override void InitRabbitMQObjs()
    {




        _rabbitMQObjs.Add(new RabbitMQObj()
        {
            ExchangeName = "llmStartSession" + _serviceID,
            FuncName = "llmStartSession",
            MessageTimeout = 600000
        });
        _rabbitMQObjs.Add(new RabbitMQObj()
        {
            ExchangeName = "llmUserInput" + _serviceID,
            FuncName = "llmUserInput",
            MessageTimeout = 600000
        });
        _rabbitMQObjs.Add(new RabbitMQObj()
        {
            ExchangeName = "llmRemoveSession" + _serviceID,
            FuncName = "llmRemoveSession",
            MessageTimeout = 60000
        });
        _rabbitMQObjs.Add(new RabbitMQObj()
        {
            ExchangeName = "llmStopRequest" + _serviceID,
            FuncName = "llmStopRequest",
            MessageTimeout = 60000
        });
        _rabbitMQObjs.Add(new RabbitMQObj()
        {
            ExchangeName = "queryIndexResult" + _serviceID,
            FuncName = "queryIndexResult",
            MessageTimeout = 60000
        });


    }
    protected override async Task<ResultObj> DeclareConsumers()
    {
        var result = new ResultObj();
        result.Success = true;
        try
        {
            foreach (var rabbitMQObj in _rabbitMQObjs)
            {
                if (rabbitMQObj.ConnectChannel == null)
                {
                    result.Message += $" Error : RabbitListener Connect Channel not open for Exchange {rabbitMQObj.ExchangeName}";
                    result.Success = false;
                    _logger.LogCritical(result.Message);
                    return result;
                }
                rabbitMQObj.Consumer = new AsyncEventingBasicConsumer(rabbitMQObj.ConnectChannel);


                await rabbitMQObj.ConnectChannel.BasicConsumeAsync(
                    queue: rabbitMQObj.QueueName,
                    autoAck: false,
                    consumer: rabbitMQObj.Consumer
                );

                if (rabbitMQObj.Consumer == null)
                {
                    result.Message += $" Error : RabbitListener can't create Consumer for queue  {rabbitMQObj.QueueName}";
                    result.Success = false;
                    _logger.LogCritical(result.Message);
                    return result;
                }
                switch (rabbitMQObj.FuncName)
                {
                    case "llmStartSession":
                        await rabbitMQObj.ConnectChannel.BasicQosAsync(prefetchSize: 0, prefetchCount: 1, global: false);
                        rabbitMQObj.Consumer.ReceivedAsync += async (model, ea) =>
                    {
                        try
                        {
                            _ = StartSession(ConvertToObject<LLMServiceObj>(model, ea));
                            await rabbitMQObj.ConnectChannel.BasicAckAsync(ea.DeliveryTag, false);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(" Error : RabbitListener.DeclareConsumers.llmStartSession " + ex.Message);
                        }
                    };
                        break;
                    case "llmStopRequest":
                        await rabbitMQObj.ConnectChannel.BasicQosAsync(prefetchSize: 0, prefetchCount: 1, global: false);
                        rabbitMQObj.Consumer.ReceivedAsync += async (model, ea) =>
                    {
                        try
                        {
                            _ = StopRequest(ConvertToObject<LLMServiceObj>(model, ea));
                            await rabbitMQObj.ConnectChannel.BasicAckAsync(ea.DeliveryTag, false);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(" Error : RabbitListener.DeclareConsumers.llmStopRequest " + ex.Message);
                        }
                    };
                        break;
                    case "llmRemoveSession":
                        await rabbitMQObj.ConnectChannel.BasicQosAsync(prefetchSize: 0, prefetchCount: 1, global: false);
                        rabbitMQObj.Consumer.ReceivedAsync += async (model, ea) =>
                    {
                        try
                        {
                            _ = RemoveSession(ConvertToObject<LLMServiceObj>(model, ea));
                            await rabbitMQObj.ConnectChannel.BasicAckAsync(ea.DeliveryTag, false);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(" Error : RabbitListener.DeclareConsumers.llmRemoveSession " + ex.Message);
                        }
                    };
                        break;
                    case "llmUserInput":
                        await rabbitMQObj.ConnectChannel.BasicQosAsync(prefetchSize: 0, prefetchCount: 1, global: false);
                        rabbitMQObj.Consumer.ReceivedAsync += async (model, ea) =>
                    {
                        try
                        {
                            _ = UserInput(ConvertToObject<LLMServiceObj>(model, ea));
                            await rabbitMQObj.ConnectChannel.BasicAckAsync(ea.DeliveryTag, false);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(" Error : RabbitListener.DeclareConsumers.llmUserInput " + ex.Message);
                        }
                    };
                        break;
                    case "queryIndexResult":
                        await rabbitMQObj.ConnectChannel.BasicQosAsync(prefetchSize: 0, prefetchCount: 1, global: false);
                        rabbitMQObj.Consumer.ReceivedAsync += async (model, ea) =>
                        {
                            try
                            {
                                 QueryIndexResult(ConvertToObject<QueryIndexRequest>(model, ea));
                                await rabbitMQObj.ConnectChannel.BasicAckAsync(ea.DeliveryTag, false);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(" Error : RabbitListener.DeclareConsumers.queryIndexResult " + ex.Message);
                            }
                        };
                        break;

                }
            }
            if (result.Success) result.Message += " Success : Declared all consumers ";
        }
        catch (Exception e)
        {
            string message = " Error : failed to declare consumers. Error was : " + e.ToString() + " . ";
            result.Message += message;
            _logger.LogError(result.Message);
            result.Success = false;
        }
        return result;
    }
    public async Task<ResultObj> StartSession(LLMServiceObj? llmServiceObj)
    {
        var result = new ResultObj();
        result.Success = false;
        result.Message = "MessageAPI : StartSession : ";
        if (llmServiceObj == null)
        {
            result.Message += " Error : llmServiceObj is null.";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }

        try
        {
            llmServiceObj = await _llmService.StartProcess(llmServiceObj);
            result.Message = llmServiceObj.ResultMessage;
            result.Success = llmServiceObj.ResultSuccess;


        }
        catch (Exception e)
        {
            result.Message = e.Message;
            result.Success = false;
        }

        if (result.Success) _logger.LogInformation(result.Message);
        else _logger.LogError(result.Message);
        return result;
    }

    public async Task<ResultObj> RemoveSession(LLMServiceObj? llmServiceObj)
    {
        var result = new ResultObj();
        result.Success = false;
        result.Message = "MessageAPI : RemoveSession : ";
        if (llmServiceObj == null)
        {
            return new ResultObj() { Message = " Error : llmServiceObj is null." };
        }

        try
        {
            result = await _llmService.RemoveAllSessionIdProcesses(llmServiceObj);

        }
        catch (Exception e)
        {
            result.Message = e.Message;
            result.Success = false;
        }

        if (result.Success) _logger.LogInformation(result.Message);
        else _logger.LogError(result.Message);
        return result;
    }


    public async Task<ResultObj> UserInput(LLMServiceObj? serviceObj)
    {
        var result = new ResultObj();
        result.Success = false;
        result.Message = "MessageAPI : UserInput : ";
        if (serviceObj == null)
        {
            result.Message += " Error : serviceObj is null.";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }
        if (serviceObj.UserInput == null)
        {
            result.Message += " Error : serviceObj.UserInput is null";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }
        if (serviceObj.UserInput == "")
        {
            result.Message += " Error : serviceObj.UserInput is empty.";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }
        //_logger.LogInformation($" Start User Input {serviceObj.UserInput}");
        try
        {

            var resultService = await _llmService.SendInputAndGetResponse(serviceObj);
            result.Message += resultService.Message;
            result.Success = resultService.Success;
        }
        catch (Exception e)
        {
            result.Message = e.Message;
            result.Success = false;

        }
        if (!result.Success) _logger.LogError(result.Message);
        return result;
    }

    public async Task<ResultObj> StopRequest(LLMServiceObj? serviceObj)
    {
        var result = new ResultObj();
        result.Success = false;
        result.Message = "MessageAPI : StopRequest : ";
        if (serviceObj == null)
        {
            result.Message += " Error : serviceObj is null.";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }
        if (serviceObj.UserInput == null)
        {
            result.Message += " Error : serviceObj.UserInput is null";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }

        //_logger.LogInformation($" Start User Input {serviceObj.UserInput}");
        try
        {

            result = await _llmService.StopRequest(serviceObj);

        }
        catch (Exception e)
        {
            result.Message = e.Message;
            result.Success = false;

        }
        if (!result.Success) _logger.LogError(result.Message);
        return result;
    }

        public ResultObj QueryIndexResult(QueryIndexRequest? queryIndexRequest)
    {
        var result = new ResultObj();
        result.Success = false;
        result.Message = "MessageAPI : QueryIndexResult : ";

        if (queryIndexRequest == null)
        {
            result.Message += " Error : queryIndexRequest is null.";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }

        try
        {
            // Extract the RAG data from the QueryResults
            var ragData = string.Join("\n", queryIndexRequest.QueryResults.Select(qr => qr.Output));

            // Set the result
            result.Success = queryIndexRequest.Success;
            result.Message = queryIndexRequest.Message;
            result.Data = ragData; // Store the RAG data in the ResultObj

            // Signal the completion of the query
            _queryCoordinator.CompleteQuery(queryIndexRequest.MessageID, ragData);
        }
        catch (Exception e)
        {
            result.Message = e.Message;
            result.Success = false;

            // Signal the completion of the query even if it fails
            _queryCoordinator.CompleteQuery(queryIndexRequest.MessageID, "");
        }

        if (!result.Success) _logger.LogError(result.Message);
        return result;
    }

}
