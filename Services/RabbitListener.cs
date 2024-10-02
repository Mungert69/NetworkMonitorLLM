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


}

public class RabbitListener : RabbitListenerBase, IRabbitListener
{
    protected ILLMService _llmService;
    private string _serviceID="monitor";

    public RabbitListener(ILLMService llmService, ILogger<RabbitListenerBase> logger, ISystemParamsHelper systemParamsHelper) : base(logger, DeriveSystemUrl(systemParamsHelper))
    {

        _llmService = llmService;
        _serviceID=systemParamsHelper.GetSystemParams().ServiceID ?? "monitor";
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
            ExchangeName = "llmStartSession"+_serviceID,
            FuncName = "llmStartSession",
            MessageTimeout = 600000
        });
        _rabbitMQObjs.Add(new RabbitMQObj()
        {
            ExchangeName = "llmUserInput"+_serviceID,
            FuncName = "llmUserInput",
            MessageTimeout = 600000
        });
        _rabbitMQObjs.Add(new RabbitMQObj()
        {
            ExchangeName = "llmRemoveSession"+_serviceID,
            FuncName = "llmRemoveSession",
            MessageTimeout = 600000
        });



    }
    protected override ResultObj DeclareConsumers()
    {
        var result = new ResultObj();
        result.Success = true;
        try
        {
            _rabbitMQObjs.ForEach(rabbitMQObj =>
        {
            if (rabbitMQObj.ConnectChannel == null)
            {
                result.Message += $" Error : RabbitListener Connect Channel not open for Exchange {rabbitMQObj.ExchangeName}";
                result.Success = false;
                _logger.LogCritical(result.Message);
                return;
            }
            rabbitMQObj.Consumer = new EventingBasicConsumer(rabbitMQObj.ConnectChannel);

            if (rabbitMQObj.Consumer == null)
            {
                result.Message += $" Error : RabbitListener can't create Consumer for queue  {rabbitMQObj.QueueName}";
                result.Success = false;
                _logger.LogCritical(result.Message);
                return;
            }
            switch (rabbitMQObj.FuncName)
            {
                case "llmStartSession":
                    rabbitMQObj.ConnectChannel.BasicQos(prefetchSize: 0, prefetchCount: 1, global: false);
                    rabbitMQObj.Consumer.Received += async (model, ea) =>
                {
                    try
                    {
                        result = await StartSession(ConvertToObject<LLMServiceObj>(model, ea));
                        rabbitMQObj.ConnectChannel.BasicAck(ea.DeliveryTag, false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(" Error : RabbitListener.DeclareConsumers.llmStartSession " + ex.Message);
                    }
                };
                    break;
                case "llmRemoveSession":
                    rabbitMQObj.ConnectChannel.BasicQos(prefetchSize: 0, prefetchCount: 1, global: false);
                    rabbitMQObj.Consumer.Received += async (model, ea) =>
                {
                    try
                    {
                        result = await RemoveSession(ConvertToObject<LLMServiceObj>(model, ea));
                        rabbitMQObj.ConnectChannel.BasicAck(ea.DeliveryTag, false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(" Error : RabbitListener.DeclareConsumers.llmRemoveSession " + ex.Message);
                    }
                };
                    break;
                case "llmUserInput":
                    rabbitMQObj.ConnectChannel.BasicQos(prefetchSize: 0, prefetchCount: 1, global: false);
                    rabbitMQObj.Consumer.Received += async (model, ea) =>
                {
                    try
                    {
                        result = await UserInput(ConvertToObject<LLMServiceObj>(model, ea));
                        rabbitMQObj.ConnectChannel.BasicAck(ea.DeliveryTag, false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(" Error : RabbitListener.DeclareConsumers.llmUserInput " + ex.Message);
                    }
                };
                    break;

            }
        });
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
            llmServiceObj = await _llmService.RemoveProcess(llmServiceObj);
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


    public async Task<ResultObj> UserInput(LLMServiceObj? serviceObj)
    {
        var result = new ResultObj();
        result.Success = false;
        result.Message = "MessageAPI : UserInput : ";
       if (serviceObj == null )
        {
            result.Message += " Error : serviceObj is null.";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }
         if (serviceObj.UserInput == null )
        {
            result.Message += " Error : serviceObj.UserInput is null";
            _logger.LogError(result.Message);
            result.Success = false;
            return result;
        }
          if (serviceObj.UserInput == "" )
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

}
