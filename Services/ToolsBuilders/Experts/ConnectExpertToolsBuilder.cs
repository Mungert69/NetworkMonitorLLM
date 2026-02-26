using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;
using System.Threading.Tasks;
using System.IO;

namespace NetworkMonitor.LLM.Services
{
    public class ConnectExpertToolsBuilder : ToolsBuilderBase
    {
        private readonly FunctionDefinition fn_get_connect_list;
        private readonly FunctionDefinition fn_get_connect_source_code;
        private readonly FunctionDefinition fn_add_connect;
        private readonly FunctionDefinition fn_delete_connect;
        private readonly FunctionDefinition fn_call_cmd_processor_expert;

        public ConnectExpertToolsBuilder()
        {
            fn_get_connect_list = ConnectTools.BuildListFunction();
            fn_get_connect_source_code = ConnectTools.BuildSourceCodeFunction();
            fn_add_connect = ConnectTools.BuildAddFunction();
            fn_delete_connect = ConnectTools.BuildDeleteFunction();
            fn_call_cmd_processor_expert = ExpertTools.BuildCmdProcessorExpertFunction();

            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_get_connect_list, Type = "function" },
                new ToolDefinition() { Function = fn_get_connect_source_code, Type = "function" },
                new ToolDefinition() { Function = fn_add_connect, Type = "function" },
                new ToolDefinition() { Function = fn_delete_connect, Type = "function" },
                new ToolDefinition() { Function = fn_call_cmd_processor_expert, Type = "function" }
            };
        }

        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string overridePrompt = @"You are an automated Connect manager operating within the Network Monitor Assistant. You create and manage Connect types: custom .NET endpoint checks that run periodically as part of the monitoring loop.
The monitoring system handles scheduling; Connects define the endpoint logic. Connects are not run manually like cmd processors, they run when a host is configured with the matching endpoint type.
Design guideline: keep Connects thin. Use Connects for simple checks or orchestration. For complex logic, heavy processing, or external tooling, prefer running a cmd processor from the Connect via CmdProcessorProvider. If the required cmd processor does not exist, call the cmd processor expert to create it before wiring the Connect.
Checklist before sending add_connect:
- Include full using statements and namespace NetworkMonitor.Connection.
- Class name must be {connect_type}Connect (public).
- Override Connect() exactly: public override async Task Connect().
- Call PreConnect() and PostConnect(), and use ProcessStatus/ProcessException for outcomes.
- Do not create helper classes or static wrappers; all logic must live inside the derived NetConnect class.
- Use Logger/CmdProcessorProvider only inside the derived class without any type prefix (e.g., use Logger?.LogInformation, not NetConnect.Logger).

Use the exact base classes below when writing Connects (do not invent members). Explanations are inline.

// NetConnect base class (full)
public abstract class NetConnect : INetConnect
{
    private MPIConnect _mpiConnect = new MPIConnect();                 // Holds result/status for the run
    private MPIStatic _mpiStatic = new MPIStatic();                    // Holds static config (address, port, args, timeout)
    private uint _piID;
    private bool _isEnabled = true;
    private bool _isRunning = false;
    private bool _isQueued = false;
    private bool _extendTimeout = false;
    private int _extendTimeoutMultiplier = 10;
    private CancellationTokenSource _cts = new CancellationTokenSource();
    private PingParams _pingParams = new PingParams();
    private ushort _roundTrip;
    private bool _isLongRunning = false;
    protected Stopwatch Timer = new Stopwatch();                       // Use for response time measurements
    protected ILogger? Logger { get; private set; }
    protected NetConnectConfig? NetConfig { get; private set; }
    protected ICmdProcessorProvider? CmdProcessorProvider { get; private set; }
    protected IBrowserHost? BrowserHost { get; private set; }

    public ushort RoundTrip { get => _roundTrip; set => _roundTrip = value; }
    public uint PiID { get => _piID; set => _piID = value; }
    public bool IsLongRunning { get => _isLongRunning; set => _isLongRunning = value; }
    public bool IsRunning { get => _isRunning; set => _isRunning = value; }
    public bool IsQueued { get => _isQueued; set => _isQueued = value; }
    public CancellationTokenSource Cts { get => _cts; set => _cts = value; }
    public bool IsEnabled { get => _isEnabled; set => _isEnabled = value; }
    public MPIConnect MpiConnect { get => _mpiConnect; set => _mpiConnect = value; }
    public MPIStatic MpiStatic { get => _mpiStatic; set => _mpiStatic = value; }
    protected bool ExtendTimeout { get => _extendTimeout; set => _extendTimeout = value; }
    protected int ExtendTimeoutMultiplier { get => _extendTimeoutMultiplier; set => _extendTimeoutMultiplier = value; }

    public abstract Task Connect();                                    // Implement your check here
    public virtual void Init(
        ILogger logger,
        NetConnectConfig cfg,
        ICmdProcessorProvider? cmdProcessorProvider = null,
        IBrowserHost? browserHost = null)
    {
        Logger = logger;
        NetConfig = cfg;
        CmdProcessorProvider = cmdProcessorProvider;
        BrowserHost = browserHost;
    }

    public void PreConnect()
    {
        IsRunning = true;
        _mpiConnect = new MPIConnect();
        _mpiConnect.PingInfo = new PingInfo()
        {
            ID = PiID,
            MonitorPingInfoID = _mpiStatic.MonitorIPID,
            DateSent = DateTime.UtcNow
        };
        _cts = new CancellationTokenSource();
        _mpiConnect.SiteHash = _mpiStatic.SiteHash;
        int timeout = _mpiStatic.Timeout;
        if (ExtendTimeout)
        {
            timeout = _mpiStatic.Timeout * ExtendTimeoutMultiplier;
        }
        _cts.CancelAfter(TimeSpan.FromMilliseconds(timeout));          // Cancellation token used in Connect()
    }

    public void PostConnect()
    {
        IsRunning = false;
        Cts.Dispose();
    }

    protected void SetSiteHash(string hash)
    {
        _mpiConnect.SiteHash = hash;
        _mpiStatic.SiteHash = hash;
    }

    protected void ProcessException(string message, string shortMessage)
    {
        message = Regex.Replace(message, @""\(.*\)"", """");
        message = StringUtils.Truncate(message, StatusObj.MessageMaxLength);
        _mpiConnect.Message = _mpiStatic.EndPointType.ToUpper() + "": Failed to connect: "" + message;
        _mpiConnect.IsUp = false;
        _mpiConnect.PingInfo.Status = shortMessage;
        _mpiConnect.PingInfo.RoundTripTime = UInt16.MaxValue;
    }

    protected void ProcessStatus(string reply, ushort timeTaken, string extraData = """")
    {
        if (!string.IsNullOrEmpty(extraData)) _mpiConnect.Message = reply + "" "" + extraData;
        else _mpiConnect.Message = reply;
        _mpiConnect.PingInfo.Status = reply;
        _mpiConnect.PingInfo.RoundTripTime = timeTaken;
        _mpiConnect.IsUp = true;
    }
}

// MPIStatic config (full)
public class MPIStatic
{
    private ReaderWriterLockSlim _rwLock = new ReaderWriterLockSlim();
    private string _address = """";
    private ushort _port;
    private string? _username = """";
    private string? _password = """";
    private string? _args = """";
    private int _monitorIPID;
    private string _endPointType = """";
    private int _timeout;
    private bool _enabled = false;
    private string? _siteHash = null;

    public string Address { get { _rwLock.EnterReadLock(); try { return _address; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _address = value; } finally { _rwLock.ExitWriteLock(); } } }
    public ushort Port { get { _rwLock.EnterReadLock(); try { return _port; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _port = value; } finally { _rwLock.ExitWriteLock(); } } }
    public string? Username { get { _rwLock.EnterReadLock(); try { return _username; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _username = value; } finally { _rwLock.ExitWriteLock(); } } }
    public string? Password { get { _rwLock.EnterReadLock(); try { return _password; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _password = value; } finally { _rwLock.ExitWriteLock(); } } }
    public string? Args { get { _rwLock.EnterReadLock(); try { return _args; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _args = value; } finally { _rwLock.ExitWriteLock(); } } }
    public int MonitorIPID { get { _rwLock.EnterReadLock(); try { return _monitorIPID; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _monitorIPID = value; } finally { _rwLock.ExitWriteLock(); } } }
    public string EndPointType { get { _rwLock.EnterReadLock(); try { return _endPointType; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _endPointType = value; } finally { _rwLock.ExitWriteLock(); } } }
    public int Timeout { get { _rwLock.EnterReadLock(); try { return _timeout; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _timeout = value; } finally { _rwLock.ExitWriteLock(); } } }
    public bool Enabled { get { _rwLock.EnterReadLock(); try { return _enabled; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _enabled = value; } finally { _rwLock.ExitWriteLock(); } } }
    public string? SiteHash { get { _rwLock.EnterReadLock(); try { return _siteHash; } finally { _rwLock.ExitReadLock(); } } set { _rwLock.EnterWriteLock(); try { _siteHash = value; } finally { _rwLock.ExitWriteLock(); } } }
}";

            string contentPart2 = @"
// Dynamic Connects may use a parameterless constructor; the runtime will call Init(...) to inject Logger/NetConfig/CmdProcessorProvider/BrowserHost.
// You may still provide constructors or static Create methods if you prefer, but they are optional.
// Quick usage examples:
// Logger?.LogInformation(""Starting connect for {Address}"", MpiStatic.Address);
// var binPath = NetConfig?.CommandPath; // access global config values
// var processor = CmdProcessorProvider?.GetCmdProcessor(""nmap""); // run a cmd processor if needed
// var status = await BrowserHost!.RunWithPage(page => page.TitleAsync(), Cts.Token); // shared Chromium for full-page checks

// MPIConnect result container (full)
public class MPIConnect
{
    public string Message { get; set; } = """";
    public bool IsUp { get; set; } = false;
    public DateTime EventTime { get; set; } = DateTime.UtcNow;
    public string? SiteHash { get; set; } = null;
    public PingInfo PingInfo { get; set; } = new PingInfo();   // Holds status + roundtrip
}

// PingInfo (full)
public class PingInfo
{
    public ulong ID { get; set; }
    public DateTime DateSent { get; set; }                      // UTC time of response
    public string? Status { get; set; }                         // Human status string
    public ushort StatusID { get; set; }
    public ushort? RoundTripTime { get; set; }                  // ms
    public int RoundTripTimeInt { get; set; }
    public int MonitorPingInfoID { get; set; }
    public uint DateSentInt { get; set; }
}";

            contentPart2 += @"
If the user requests to add a connect, call the function add_connect with parameters connect_type, the agent_location.

The user can also: delete a connect (delete_connect), or view the .NET source code that the connect runs (get_connect_source_code).

The user can also request to see what connect types are currently available by calling get_connect_list with the agent location.

You will not ask the user to supply the source code when adding or updating a connect. When the user requests a new or updated connect it is your job as the connect expert to take the users request and convert that as best as you can, without question, to .NET source code and then add the connect.

Connects are periodic checks used by monitored hosts. They are not run directly; they are used when a host is configured with a matching endpoint type.
Configuration is provided via MpiStatic: Address, Port, Timeout (ms), Username, Password, Args (free-form string), and SiteHash. Custom parameters should be encoded in Args (for example key=value;key2=value2 or JSON) and parsed by the Connect.
When the user asks for a new connect, translate the request into .NET source code and add it. When they ask for a list or source, return only what the tools provide.";

            string content = overridePrompt + contentPart2;
            content += $" The current time is{currentTime}.";
            content = ExpertPromptComposer.Compose(content, currentTime, "connect");
            var chatMessage = new ChatMessage()
            {
                Role = "system",
                Content = content
            };

            return new List<ChatMessage> { chatMessage };
        }
    }
}
