import os
import json
import logging
import requests
from datetime import datetime
from llama_cpp import Llama  # Use llama-cpp-python

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO  # Change to logging.DEBUG for more details
)

# GitHub API settings
GITHUB_REPO = "ggml-org/llama.cpp"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/commits"
LAST_COMMIT_FILE = "last_commit.txt"

# Local GGUF model
LOCAL_MODEL_PATH = "./Qwen2.5-3B-Instruct-bf16-q4_k.gguf"

# Load quantized GGUF model using llama-cpp-python
logging.info("Loading quantized GGUF model...")
try:
    llm = Llama(model_path=LOCAL_MODEL_PATH)  # Loading model via llama-cpp-python
    logging.info("Model loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load model: {e}")
    exit(1)

def fetch_latest_commit():
    """Fetch latest commit from GitHub API and return its details."""
    logging.info(f"Fetching latest commit from {GITHUB_REPO}...")
    try:
        response = requests.get(GITHUB_API_URL, timeout=10)
        response.raise_for_status()
        commits = response.json()
        if not commits:
            logging.warning("No commits found!")
            return None
        latest_commit = commits[0]
        logging.debug(f"Latest commit data: {json.dumps(latest_commit, indent=2)}")
        return latest_commit
    except requests.RequestException as e:
        logging.error(f"GitHub API error: {e}")
        return None

def analyze_commit(commit):
    """Analyze commit message and file changes to detect new models."""
    commit_sha = commit.get("sha", "UNKNOWN_SHA")
    message = commit.get("commit", {}).get("message", "No commit message found")

    logging.info(f"Analyzing commit {commit_sha}...")
    logging.debug(f"Commit message: {message}")

    prompt = (
        "You are an AI assistant. Analyze the following commit message and determine if it adds a new AI model.\n"
        "Respond ONLY in valid JSON format. Your response must be a complete JSON object with no extra text.\n"
        "The response should look like this:\n"
        "{\n"
        '  \"is_new_model\": true/false,\n'
        '  \"reason_for_answer\": \"Explain why or why not.\"\n'
        "}\n"
        "Return only the JSON structure, without any extra words, explanations, or formatting.\n"
        f"Commit message:\n\"{message}\""
    )

    try:
        llm_response = llm(
            prompt,
            max_tokens=300,  # Adjust token size if needed
            stop=None,  # Avoid prematurely stopping
            echo=False
        )

        # Log the raw LLM response
        response_text = llm_response.get("choices", [{}])[0].get("text", "").strip()
        logging.info(f"Raw LLM Response: {response_text}")

        # Validate that the response starts with "{", indicating valid JSON
        if not response_text or not response_text.startswith("{"):
            raise ValueError(f"Unexpected response format: {response_text}")

        # Try parsing the response as JSON
        llm_output = json.loads(response_text)

        is_new_model = llm_output.get("is_new_model", False)
        reason = llm_output.get("reason_for_answer", "No reason provided.")

        logging.info(f"LLM Decision: {is_new_model}")
        logging.info(f"LLM Reason: {reason}")

        return is_new_model

    except (json.JSONDecodeError, ValueError) as e:
        logging.error(f"Invalid LLM response format: {e}")
        logging.error(f"Raw LLM Response (before failure): {response_text}")  # Log raw response
        return False

def download_model():
    """Download model from Hugging Face and convert it to GGUF format."""
    logging.info(f"Downloading model from Hugging Face...")
    try:
        os.system(f"huggingface-cli download {HUGGINGFACE_MODEL} --local-dir {LOCAL_MODEL_DIR}")
        logging.info("Download completed.")

        logging.info("Converting to GGUF format...")
        os.system(f"python3 ./convert-llama3-to-gguf.py --input {LOCAL_MODEL_DIR} --output {LOCAL_MODEL_PATH}")
        logging.info("Conversion to GGUF completed.")
    except Exception as e:
        logging.error(f"Model download or conversion failed: {e}")

def main():
    """Main monitoring function."""
    last_commit = None
    if os.path.exists(LAST_COMMIT_FILE):
        with open(LAST_COMMIT_FILE, "r") as f:
            last_commit = f.read().strip()

    commit = fetch_latest_commit()
    if not commit:
        logging.info("No new commits found.")
        return

    commit_sha = commit.get("sha", "UNKNOWN_SHA")
    if commit_sha == last_commit:
        logging.info("No new commits since last check.")
        return

    logging.info(f"Checking commit {commit_sha}...")

    if analyze_commit(commit):
        logging.info("New model detected! Downloading and converting...")
        download_model()
        with open(LAST_COMMIT_FILE, "w") as f:
            f.write(commit_sha)
    else:
        logging.info("No model-related changes detected.")

if __name__ == "__main__":
    main()

