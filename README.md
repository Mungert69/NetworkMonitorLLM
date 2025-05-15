
# NetworkMonitorLLM Technical Documentation

## Core Purpose
A modular LLM integration framework designed specifically for network monitoring systems that:
- Provides a unified interface for multiple LLM backends
- Manages conversational state for monitoring workflows
- Implements function calling for network operations
- Handles resource allocation for local models

## Architectural Components

### 1. LLMService (Facade Layer)
```csharp
public interface ILLMService {
    Task<LLMServiceObj> StartProcess(LLMServiceObj llmServiceObj);
    Task<ResultObj> RemoveAllSessionIdProcesses(LLMServiceObj llmServiceObj);
    Task<ResultObj> StopRequest(LLMServiceObj llmServiceObj);
    Task<ResultObj> SendInputAndGetResponse(LLMServiceObj serviceObj);
}
````

* Manages session lifecycle (creation/termination)
* Routes requests to appropriate runner
* Handles cross-cutting concerns (logging, error handling)
* Maintains session state via `ConcurrentDictionary<string, Session>`

### 2. Runner Implementations

#### OpenAIRunner

```csharp
public class OpenAIRunner : ILLMRunner {
    private OpenAIService _openAiService;
    private List<ChatMessage> _history;
    private SemaphoreSlim _openAIRunnerSemaphore;
    
    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj) {
        // Handles:
        // - API communication with OpenAI
        // - Function call processing
        // - Conversation history management
        // - Token limit enforcement
    }
}
```

* OpenAI API integration
* Manages chat history with token-aware truncation
* Implements tool call handling
* Uses semaphore for thread safety

#### LLMProcessRunner

```csharp
public class LLMProcessRunner : ILLMRunner {
    private ConcurrentDictionary<string, ProcessWrapper> _processes;
    private ConcurrentDictionary<string, ITokenBroadcaster> _tokenBroadcasters;
    
    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj) {
        // Manages:
        // - Local llama.cpp processes
        // - Adaptive CPU core allocation
        // - Streaming token output
        // - Custom function call format (XML-based)
    }
}
```

* Local LLM process manager
* Implements custom token streaming
* Handles resource allocation (CPU cores/threads)
* Supports prompt caching

### 3. Supporting Components

#### Session Management

```csharp
public class Session {
    public string FullSessionId { get; set; }
    public ILLMRunner? Runner { get; set; }
    public HistoryDisplayName HistoryDisplayName { get; set; }
}
```

* Tracks runner instances
* Maintains conversation metadata
* Enables history persistence

#### Message Processing

```csharp
public interface ILLMResponseProcessor {
    Task ProcessLLMOutput(LLMServiceObj serviceObj);
    Task ProcessFunctionCall(LLMServiceObj functionResponseServiceObj);
    bool AreAllFunctionsProcessed(string messageId);
}
```

* Handles output routing
* Manages function call state
* Implements response streaming

## Core Workflows

### 1. Session Initialization

1. Client requests new session via `StartProcess()`
2. Factory creates appropriate runner (OpenAI/LLama)
3. Runner initializes with system prompts
4. Session added to tracking dictionary

### 2. Message Processing
```mermaid
sequenceDiagram
    participant Client
    participant LLMService
    participant Runner
    participant LLM
    participant ResponseProcessor

    Client->>LLMService: SendInputAndGetResponse()
    LLMService->>Runner: Route to appropriate runner
    Runner->>LLM: Forward query
    
    alt OpenAI
        LLM-->>Runner: API response
    else LLama
        LLM-->>Runner: Streamed tokens
    end
    
    Runner->>ResponseProcessor: Process output
    ResponseProcessor-->>Client: Return results
```

### 3. Function Calling

1. LLM generates function request
2. Runner parses and validates request
3. System executes network operation
4. Results formatted and returned to LLM
5. Response incorporated into conversation

## Key Technical Features

1. **Hybrid Backend Support**

   * Seamless switching between cloud/local LLMs
   * Consistent interface regardless of backend

2. **Conversation Management**

   * Token-aware history truncation
   * Session persistence
   * Context-aware prompting

3. **Resource Optimization**

   * Dynamic CPU core allocation
   * Memory monitoring
   * Process isolation

4. **Network Integration**

   * Pre-built monitoring functions
   * Alert correlation
   * Log analysis templates

## Development Guide

### Extending the System

**Adding New Backends:**

1. Implement `ILLMRunner`
2. Register in DI container
3. Add configuration schema

**Custom Functions:**

1. Create function definition
2. Implement handler
3. Register in tools builder

### Building from Source

```bash
# Clone repository
git clone https://github.com/NetworkMonitorLLM/core.git

# Restore dependencies
dotnet restore

# Build solution
dotnet build -c Release
```

## Contribution Guidelines

* Follow existing architectural patterns
* Maintain interface compatibility
* Include unit tests for new features
* Document configuration changes
* 
## 🚀 Live Demo and Examples

Explore real-world examples of the system in action:

- 🔬 **ReadyForQuantum Demo (Hugging Face Space)**  
  Interactive demo showcasing quantum-aware network analysis and LLM-driven diagnostics.  
  [https://huggingface.co/spaces/Mungert/ReadyForQuantum](https://huggingface.co/spaces/Mungert/ReadyForQuantum)

- 🌐 **Official Project Site**  
  Detailed use cases, blog posts, and background on post-quantum security and LLM integration.  
  [https://readyforquantum.com](https://readyforquantum.com)



