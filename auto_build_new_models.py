import os
import json
import logging
import requests
import re
import subprocess
import shutil
import sys
import time
from datetime import datetime
from llama_cpp import Llama, LlamaGrammar
from huggingface_hub import HfApi

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# GitHub API settings
GITHUB_REPO = "ggml-org/llama.cpp"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/commits"
LAST_COMMIT_FILE = "last_commit.txt"
COMMITS_CACHE_FILE = "commits_cache.json"  # File to cache fetched commits
GITHUB_TOKEN = "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"  # Add your token here
HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
MAX_TOKENS = 4096
MODELS_JSON_PATH = "models-complete.json"
# Local GGUF model
LOCAL_MODEL_PATH = "./Meta-Llama-3-8B-Instruct-q4_k_m.gguf"
GRAMMAR_FILE_PATH = "./llama.cpp/grammars/json.gbnf"  # Path to your JSON grammar file
LOCK_FILE = "model_conversion.lock"


# Load the JSON grammar
logging.info("Loading JSON grammar...")
try:
    with open(GRAMMAR_FILE_PATH, 'r') as file:
        grammar_content = file.read()
    grammar = LlamaGrammar.from_string(grammar_content)
    logging.info("Grammar loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load grammar: {e}")
    exit(1)

def load_catalog():
    """Load or initialize the model catalog."""
    if os.path.exists(MODEL_CATALOG_FILE):
        try:
            with open(MODEL_CATALOG_FILE, "r") as f:
                catalog = json.load(f)
            return catalog
        except json.JSONDecodeError:
            logging.error("Failed to parse model_catalog.json. Using empty catalog.")
            return {}
    return {}

def save_catalog(catalog):
    """Save the catalog to MODEL_CATALOG_FILE."""
    with open(MODEL_CATALOG_FILE, "w") as f:
        json.dump(catalog, f, indent=2)

def fetch_last_50_commits():
    """Fetch the last 50 commits from GitHub API and cache them."""
    logging.info(f"Fetching last 50 commits from {GITHUB_REPO}...")
    try:
        params = {"per_page": 50}  # Fetch up to 50 commits
        response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params, timeout=10)
        response.raise_for_status()
        commits = response.json()
        if not commits:
            logging.warning("No commits found!")
            return None

        logging.info(f"Fetched {len(commits)} commits from GitHub API.")

        # Cache the commits to a file
        with open(COMMITS_CACHE_FILE, "w") as f:
            json.dump(commits, f, indent=2)
        logging.info(f"Commits cached to {COMMITS_CACHE_FILE}.")

        return commits

    except requests.RequestException as e:
        logging.error(f"GitHub API error: {e}")
        return None

def load_cached_commits():
    """Load commits from the cache file if it exists."""
    if os.path.exists(COMMITS_CACHE_FILE):
        logging.info(f"Loading cached commits from {COMMITS_CACHE_FILE}...")
        with open(COMMITS_CACHE_FILE, "r") as f:
            return json.load(f)
    logging.info("No cached commits found.")
    return None

def fetch_commit_details(commit_sha):
    """Fetch details for a specific commit, including file changes and diffs."""
    logging.info(f"Fetching details for commit {commit_sha}...")
    try:
        commit_url = f"https://api.github.com/repos/{GITHUB_REPO}/commits/{commit_sha}"
        commit_response = requests.get(commit_url, headers=HEADERS, timeout=10)
        commit_response.raise_for_status()
        return commit_response.json()
    except requests.RequestException as e:
        logging.error(f"GitHub API error: {e}")
        return None

def analyze_commit(commit):
    """Analyze commit message and file changes to detect new models using the LLM."""
    # Load quantized GGUF model using llama-cpp-python with chat support
    logging.info("Loading quantized GGUF model...")
    try:
        llm = Llama(
            model_path=LOCAL_MODEL_PATH,
            n_ctx=MAX_TOKENS,
            verbose=False,
            chat_format="chatml"  # Use a native chat format for system/user messages
        )
        logging.info(f"Model loaded successfully with a context window of {MAX_TOKENS} tokens.")
    except Exception as e:
        logging.error(f"Failed to load model: {e}")
        exit(1)

    commit_sha = commit.get("sha", "UNKNOWN_SHA")
    message = commit.get("commit", {}).get("message", "No commit message found")
    files = commit.get("files", [])

    logging.info(f"Analyzing commit {commit_sha}...")
    logging.info(f"Commit message: {message}")

    # Extract relevant file changes
    file_changes = extract_relevant_file_changes(files)
    logging.info(f"Relevant file changes: {json.dumps(file_changes, indent=2)}")

    # Build the prompt messages (a list of messages with roles)
    prompt_messages = build_commit_analysis_prompt(message, file_changes)
    logging.info("LLM prompt messages: " + json.dumps(prompt_messages, indent=2))

    try:
        # Get LLM response using the chat completion API
        llm_response = llm.create_chat_completion(
            messages=prompt_messages,
            max_tokens=MAX_TOKENS,
            temperature=0.0,  # Use a low temperature for deterministic output
            grammar=grammar
        )

        # Extract and clean the response from the assistant message
        choice = llm_response.get("choices", [{}])[0]
        if "message" in choice:
            response_text = choice["message"].get("content", "").strip()
        else:
            response_text = choice.get("text", "").strip()
        logging.info(f"Raw LLM Response: {response_text}")
        # Parse and validate the response
        llm_output = parse_and_validate_llm_response(response_text)

        # Log the decision
        is_new_model = llm_output.get("is_new_model", False)
        model_name = llm_output.get("model_name_if_found", None)
        reason = llm_output.get("reason_for_answer", "No reason provided.")
        confidence = llm_output.get("confidence", "low")
        logging.info(f"LLM Decision: {is_new_model}")
        logging.info(f"LLM Confidence: {confidence}")
        logging.info(f"LLM Reason: {reason}")
        if model_name:
            logging.info(f"LLM Detected Model Name: {model_name}")

        return is_new_model, model_name

    except (json.JSONDecodeError, ValueError) as e:
        logging.error(f"Invalid LLM response format: {e}")
        logging.error(f"Raw LLM Response (before failure): {response_text}")
        return False, None

def extract_relevant_file_changes(files):
    """Extract relevant file changes for model addition detection."""
    file_changes = []
    for file in files:
        filename = file.get("filename", "")
        patch = file.get("patch", "")  # Get the patch, default to empty string if missing

        # Check if the file is relevant to model addition
        if (
            any(keyword in filename.lower() for keyword in ["convert", "hf_to_gguf", "models"])
            or filename.startswith("scripts/")
        ):
            # Include the first 10 lines of the patch (if available)
            if patch:
                patch_preview = "\n".join(patch.split("\n")[:10])
            else:
                patch_preview = "No changes preview available"
            file_changes.append({"filename": filename, "patch_preview": patch_preview})
    return file_changes

def build_commit_analysis_prompt(message, file_changes):
    """Build the prompt messages for analyzing a commit."""
    system_message = (
        "You are an AI assistant that analyzes GitHub commits to detect new AI models.\n"
        "Your task is to determine if a new AI model is being added based on the commit message and file changes.\n"
        "Respond ONLY in valid JSON format with the following structure:\n"
        "{\n"
        '  "is_new_model": true/false,\n'
        '  "model_name_if_found": "Name of the model if detected, otherwise null",\n'
        '  "confidence": "high|medium|low",\n'
        '  "reason_for_answer": "Explain why or why not."\n'
        "}\n"
        "Rules for detecting new models:\n"
        "1. A new model must be explicitly mentioned in the commit message with keywords like 'add', 'support', or 'implement'.\n"
        "2. The model name must not be 'ggml', 'llama', or any other framework name.\n"
        "3. If no relevant files are changed (e.g., model definitions, configs, or scripts), confidence must be 'low'.\n"
        "4. If the commit message mentions 'bug fix', 'optimize', or 'refactor', it is unlikely to be a new model.\n"
        "5. Analyze the C++ code changes in the patch preview to detect new models. Look for:\n"
        "   - New class definitions (e.g., 'class Mistral3Model').\n"
        "   - Model registration (e.g., 'Model.register(\"Mistral3ForConditionalGeneration\")').\n"
        "   - Architecture changes (e.g., 'model_arch = gguf.MODEL_ARCH.LLAMA').\n"
        " Here are two examples of C++ code that indicates a model is added along with the mode that was added. Model.register(\"Mistral3ForConditionalGeneration\") class Mistral3Model(LlamaModel) : this would indicate adding a new model called Mistral 3. Model.register(\"Gemma3ForCausalLM\", \"Gemma3ForConditionalGeneration\") class Gemma3Model(Model) : this would indiate adding a a new model called Gemma 3.\n"
        "\n"
        "Examples of non-model commits:\n"
        "- 'Fix quantization bugs'\n"
        "- 'Update documentation'\n"
        "- 'Add SWA rope parameters' (no relevant file changes)\n"
    )

    if file_changes:
        file_context = "Model building files have been changed. This may indicate a new model has been added:\n"
        for file in file_changes:
            file_context += (
                f"- File: {file['filename']}\n"
                f"  Changes preview:\n{file['patch_preview']}\n\n"
            )
    else:
        file_context = ("No relevant file changes were found. "
                        "This strongly suggests that no new model was added, and confidence should be low.")

    user_message = (
        "Commit message:\n"
        f"{message}\n\n"
        "File changes:\n"
        f"{file_context}"
    )

    # Return the prompt as a list of chat messages
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]
    return messages

def parse_and_validate_llm_response(response_text):
    """Parse and validate the LLM response."""
    response_text = response_text.strip()
    if not response_text.startswith("{") or not response_text.endswith("}"):
        start_idx = response_text.find("{")
        end_idx = response_text.rfind("}") + 1
        if start_idx == -1 or end_idx == -1:
            raise ValueError("No valid JSON found in LLM response.")
        response_text = response_text[start_idx:end_idx]

    llm_output = json.loads(response_text)
    required_keys = ["is_new_model", "model_name_if_found", "confidence", "reason_for_answer"]
    if not all(key in llm_output for key in required_keys):
        raise ValueError("LLM response is missing required fields.")
    if llm_output["confidence"] not in ["high", "medium", "low"]:
        raise ValueError("Invalid confidence level in LLM response.")
    return llm_output

def extract_parameter_size(model_id):
    """Extract the parameter size (in billions) from the model ID."""
    match = re.search(r"(\d+)(b|B)", model_id)
    if match:
        return int(match.group(1))
    return None

def find_huggingface_model(model_name, max_parameters=15):
    """Search for the model on Hugging Face and return its ID and base model information."""
    api = HfApi()
    models = list(api.list_models(search=model_name))
    if not models:
        return None

    filtered_models = []
    for model_info in models:
        try:
            num_parameters = None
            if hasattr(model_info, "config") and model_info.config is not None:
                num_parameters = model_info.config.get("num_parameters", None)
            if num_parameters is None:
                param_size = extract_parameter_size(model_info.modelId)
                if param_size is not None:
                    num_parameters = param_size * 1e9
            if num_parameters is not None and num_parameters <= max_parameters * 1e9:
                filtered_models.append((model_info, num_parameters))
        except Exception as e:
            logging.warning(f"Error processing model {model_info.modelId}: {e}")

    if not filtered_models:
        logging.info(f"No models found with <= {max_parameters}B parameters.")
        return None

    filtered_models.sort(key=lambda x: x[1], reverse=True)
    largest_model, num_parameters = filtered_models[0]
    base_model = None
    if hasattr(largest_model, "config") and largest_model.config is not None:
        base_model = largest_model.config.get("base_model", None)

    return {
        "model_id": largest_model.modelId,
        "base_model": base_model,
        "num_parameters": num_parameters
    }


def update_catalog_with_model(model_info, detected_model_name):
    """
    Update the model catalog with a new entry for the detected model.
    The entry is written in the format:
    "company/model": {
         "added": timestamp,
         "parameters": <number>,
         "has_config": true,
         "converted": false,
         "attempts": 0,
         "last_attempt": null,
         "success_date": null,
         "error_log": [],
         "quantizations": []
    }
    """
    catalog = load_catalog()
    model_id = model_info["model_id"]
    if model_id in catalog:
        logging.info(f"Model {model_id} already exists in the catalog. Skipping update.")
        return

    entry = {
        "added": datetime.now().isoformat(),
        "parameters": model_info.get("num_parameters", -1),
        "has_config": True,
        "converted": False,
        "attempts": 0,
        "last_attempt": None,
        "success_date": None,
        "error_log": [],
        "quantizations": []
    }
    catalog[model_id] = entry
    save_catalog(catalog)
    logging.info(f"Catalog updated with new model entry: {model_id}")

def main():
    """Main monitoring function."""
    last_commit = None
    if os.path.exists(LAST_COMMIT_FILE):
        with open(LAST_COMMIT_FILE, "r") as f:
            last_commit = f.read().strip()
        logging.info(f"Last processed commit SHA: {last_commit}")
    else:
        logging.info("No last processed commit found. Starting from the oldest commit in the batch.")

    commits = fetch_last_50_commits()
    if not commits:
        logging.info("No commits fetched.")
        return

    reversed_commits = list(reversed(commits))
    logging.info(f"Processing {len(reversed_commits)} commits in oldest to newest order.")

    start_index = 0
    if last_commit:
        for i, commit in enumerate(reversed_commits):
            if commit.get("sha") == last_commit:
                start_index = i + 1
                break
        else:
            start_index = 0

    commits_to_process = reversed_commits[start_index:]
    if not commits_to_process:
        logging.info("No new commits to process.")
        return

    logging.info(f"Found {len(commits_to_process)} new commits to process.")

    for commit in commits_to_process:
        commit_sha = commit.get("sha", "UNKNOWN_SHA")
        logging.info(f"Processing commit: {commit_sha}")

        if "files" not in commit:
            commit = fetch_commit_details(commit_sha) or commit

        is_new_model, model_name = analyze_commit(commit)

        with open(LAST_COMMIT_FILE, "w") as f:
            f.write(commit_sha)
        logging.info(f"Updated last processed commit SHA: {commit_sha}")

        if is_new_model and model_name:
            logging.info(f"New model detected: {model_name}")
            model_info = find_huggingface_model(model_name, max_parameters=15)
            if model_info:
                try:
                    update_catalog_with_model(model_info, model_name)
                except Exception as e:
                    logging.error(f"Error updating catalog: {e}")
                break  # Stop after processing the first new model
            else:
                logging.info("Model not found on Hugging Face.")

if __name__ == "__main__":
    logging.info("Starting script in a loop with a 10-minute interval.")
    while True:
        try:
            logging.info(f"Starting new iteration at {datetime.now()}")
            main()
            logging.info(f"Iteration completed at {datetime.now()}. Sleeping for 10 minutes...")
            time.sleep(600)
        except Exception as e:
            logging.error(f"An error occurred during the iteration: {e}")
            logging.error("Restarting the loop in 10 minutes...")
            time.sleep(600)

