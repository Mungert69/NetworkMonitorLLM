import ctypes
from llama_cpp import Llama
from llama_cpp.llama_cpp import llama_state_save_file, llama_state_load_file
from llama_cpp.llama_tokenizer import LlamaHFTokenizer

# Define ctypes for tokens and sizes
class llama_token(ctypes.Structure):
    _fields_ = [("value", ctypes.c_int32)]

# Define the size for the token array (adjust as needed)
TOKEN_ARRAY_SIZE = 12000

# Initialize the Llama model with CPU-only settings and local GGUF model
llm = Llama(
    model_path="/home/mahadeva/code/models/functionary-small-v2.4.Q4_0.gguf",  # Path to local model
    repo_id="meetkai/functionary-small-v2.4-GGUF",
    filename="functionary-small-v2.4.Q4_0.gguf",
    chat_format="functionary-v2",
    tokenizer=LlamaHFTokenizer.from_pretrained("meetkai/functionary-small-v2.4-GGUF"),
    n_gpu_layers=0,  # Ensure the model runs on CPU
    n_threads=8,  # Adjust the number of threads for your CPU
    cache=True,  # Enable caching
    n_ctx=12000
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "add_host",
            "description": "Add a host to be monitored",
            "parameters": {
                "type": "object",
                "properties": {
                    "detail_response": {
                        "type": "boolean",
                        "description": "Will this function echo all the values set or just necessary fields. The default is false for a faster response"
                    },
                    "address": {
                        "type": "string",
                        "description": "The host address, required"
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "The endpoint type, optional. Endpoint types are: quantum (quantum safe encryption test), http (website ping), https (ssl certificate check), httphtml (website html load), icmp (host ping), dns (dns lookup), smtp (email server helo message confirmation), rawconnect (low level raw socket connection)"
                    },
                    "port": {
                        "type": "integer",
                        "description": "The port of the service being monitored, optional. It will be zero if it is the standard port for the host end point type. Note the standard port for end point type http is 443"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "The time to wait for a timeout in milliseconds, optional. Default is 59000"
                    },
                    "email": {
                        "type": "string",
                        "description": "Do not use this field if the user IS LOGGED IN. Their login email will be used and this field will be ignored. If the user is NOT LOGGED IN then ask for an email. Alerts are sent to the user's email"
                    },
                    "agent_location": {
                        "type": "string",
                        "description": "The location of the agent monitoring this host, optional. If this is left blank an agent_location will be assigned"
                    }
                },
                "required": ["address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "edit_host",
            "description": "Edit a host's monitoring configuration",
            "parameters": {
                "type": "object",
                "properties": {
                    "detail_response": {
                        "type": "boolean",
                        "description": "Will the function echo all the values set. Default is false"
                    },
                    "auth_key": {
                        "type": "string",
                        "description": "This is a string that is used to authenticate the Edit action for a user who is not logged in. This key is returned when adding a host for the first time. It should be stored and sent with subsequent edit requests. Optional if user is logged in"
                    },
                    "id": {
                        "type": "integer",
                        "description": "This is the host id used for identifying the host, optional. It is obtained when adding a host"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Host enabled, optional"
                    },
                    "address": {
                        "type": "string",
                        "description": "Host address, optional"
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "The endpoint type, optional"
                    },
                    "port": {
                        "type": "integer",
                        "description": "The port, optional"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Time to wait for a timeout in milliseconds, optional"
                    },
                    "hidden": {
                        "type": "boolean",
                        "description": "Is the host is hidden, optional. Setting this to true effectively deletes the host from future monitoring"
                    },
                    "agent_location": {
                        "type": "string",
                        "description": "The location of the agent monitoring this host, optional"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_host_data",
            "description": "Get monitoring data for hosts",
            "parameters": {
                "type": "object",
                "properties": {
                    "detail_response": {
                        "type": "boolean",
                        "description": "Will this function provide all monitoring data for hosts. Only set to true if extra response statistics are required or agent location is required. Setting it to true will slow down the processing speed of the assistant, this can affect the user's experience"
                    },
                    "dataset_id": {
                        "type": "integer",
                        "description": "Return a set of statistical data. Data is arranged in 6 hour data sets. Set dataset_id to zero for the latest data. To view historic data set dataset_id to null and select a date range with date_start and data_end"
                    },
                    "id": {
                        "type": "integer",
                        "description": "Return host with id, optional"
                    },
                    "address": {
                        "type": "string",
                        "description": "Return host with address, optional"
                    },
                    "email": {
                        "type": "string",
                        "description": "Return hosts with this email associated, optional"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Return hosts with enabled, optional"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Return host with port, optional"
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "Return hosts with endpoint type, optional"
                    },
                    "alert_sent": {
                        "type": "boolean",
                        "description": "Return hosts that have a host down alert sent set, optional"
                    },
                    "alert_flag": {
                        "type": "boolean",
                        "description": "Return hosts that have a host down alert flag set, optional. This can be used to get hosts that are up or down"
                    },
                    "date_start": {
                        "type": "string",
                        "description": "The start time to query from, optional. When used with date_end this gives a range of times to filter on"
                    },
                    "date_end": {
                        "type": "string",
                        "description": "The end time to query to, optional"
                    },
                    "page_number": {
                        "type": "integer",
                        "description": "If not all data is returned then page the data, Page Number"
                    },
                    "agent_location": {
                        "type": "string",
                        "description": "The location of the agent monitoring this host, optional"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_host_list",
            "description": "Get host configurations",
            "parameters": {
                "type": "object",
                "properties": {
                    "detail_response": {
                        "type": "boolean",
                        "description": "Will this function provide all host config detail. Set this to true if more than address and id are required"
                    },
                    "id": {
                        "type": "integer",
                        "description": "Return host with id, optional"
                    },
                    "address": {
                        "type": "string",
                        "description": "Return host with address, optional"
                    },
                    "email": {
                        "type": "string",
                        "description": "Return hosts with this email associated, optional"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Return hosts with enabled, optional"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Return hosts with port, optional"
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "Return hosts with endpoint type, optional"
                    },
                    "page_number": {
                        "type": "integer",
                        "description": "If not all data is returned then page the data, Page Number"
                    },
                    "agent_location": {
                        "type": "string",
                        "description": "The location of the agent monitoring this host, optional"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_agents",
            "description": "Get a list of agent locations",
            "parameters": {
                "type": "object",
                "properties": {
                    "detail_response": {
                        "type": "boolean",
                        "description": "Will this function return all agent details. Set to false if only require agent locations"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "call_nmap",
            "description": "Perform a scan using a remote network scanning assistant",
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to be sent to the network scanning assistant"
                    },
                    "agent_location": {
                        "type": "string",
                        "description": "The agent location that will run the scan, optional"
                    }
                },
                "required": ["message"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "call_metasploit",
            "description": "Perform a penetration testing task using a remote assistant",
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to be sent to the penetration testing assistant, explaining the user's goal in simple language"
                    },
                    "agent_location": {
                        "type": "string",
                        "description": "The agent location that will run the task, optional"
                    }
                },
                "required": ["message"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_info",
            "description": "Get information about the user",
            "parameters": {
                "type": "object",
                "properties": {
                    "detail_response": {
                        "type": "boolean",
                        "description": "Will this function return all user details. Set to false if only basic info is required"
                    }
                }
            }
        }
    }
]
system_message = [
    {
        "role": "system",
        "content": """You are an AI assistant with access to various network monitoring and security tools. Your job is to help users manage and monitor their network infrastructure. You can add hosts for monitoring, edit host configurations, retrieve host data, get lists of hosts, manage agents, perform network scans, and conduct penetration testing tasks.

When users ask questions or make requests, use the appropriate tool to fulfill their needs. Always prioritize security and ask for clarification if a user's request is unclear or potentially risky.

Available tools:
1. add_host: Add a new host for monitoring
2. edit_host: Modify existing host configurations
3. get_host_data: Retrieve monitoring data for specific hosts
4. get_host_list: Get a list of monitored hosts
5. get_agents: Retrieve a list of agent locations
6. call_nmap: Perform network scans (use cautiously and only when explicitly requested)
7. call_metasploit: Conduct penetration testing tasks (use only when explicitly requested and with proper authorization)
8. get_user_info: Retrieve information about the current user

Remember to use these tools responsibly and always prioritize the user's security and privacy."""
    }
]
# Define a function to load the session
def load_session(file_path: str):
    context = llm.ctx  # Access the context of the Llama model
    try:
        # Prepare ctypes variables
        tokens = (ctypes.c_int32 * TOKEN_ARRAY_SIZE)()  # Initialize ctypes array for tokens
        tokens_ptr = ctypes.cast(tokens, ctypes.POINTER(ctypes.c_int32))  # Pointer to the array
        n_token_capacity = ctypes.c_size_t(len(tokens))  # Capacity
        n_token_count_out = ctypes.c_size_t()  # Output count

        # Load the session file
        success = llama_state_load_file(
            context,
            file_path.encode('utf-8'),
            tokens_ptr,  # Pass pointer to the array
            n_token_capacity,
            ctypes.pointer(n_token_count_out)  # Pointer to ctypes.c_size_t
        )
        if success:
            # Extract tokens from the array
            loaded_tokens = list(tokens[:n_token_count_out.value])
            print("State loaded successfully.")
            return loaded_tokens, n_token_count_out.value
        else:
            print("Failed to load state.")
            return None, 0
    except FileNotFoundError:
        print("No cache found, processing system message with tools...")
        return None, 0
    except Exception as e:
        print(f"An error occurred while loading the cache: {str(e)}")
        return None, 0

# Define a function to save the session
def save_session(file_path: str, tokens_list: list):
    context = llm.ctx  # Accessing the context from the Llama model
    tokens = (ctypes.c_int32 * len(tokens_list))(*tokens_list)  # Convert list to ctypes array
    n_token_count = ctypes.c_size_t(len(tokens_list))

    # Save the state
    success = llama_state_save_file(
        context,
        file_path.encode('utf-8'),
        tokens,
        n_token_count
    )
    if success:
        print("State saved successfully.")
    else:
        print("Failed to save state.")

# Load session if exists
tokens, token_count = load_session('context-session.llama')

# Process system message (with tool definitions) and save the state if no cache found
if token_count == 0:
    print("Building context")
    result = llm.create_chat_completion(messages=system_message, tools=tools, tool_choice="auto" )
    tokens_list = llm.tokenize(system_message[0]['content'].encode('utf-8'))  # Encode to UTF-8 for tokenization
    save_session('context-session.llama', tokens_list)

# Now handle new user messages (no need to resend system message with tools)
user_messages = [
    {"role": "user", "content": "add host test.com"}
]

# Generate a chat completion with new user input
result = llm.create_chat_completion(
    messages=user_messages,
    tools=tools,
    tool_choice="auto"
)

# Print the output
print(result["choices"][0]["message"])

