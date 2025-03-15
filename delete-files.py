import os
import sys
from huggingface_hub import HfApi

# Check if at least one file is provided
if len(sys.argv) < 2:
    print("Usage: python delete_from_hf.py <file1> [<file2> ...]")
    sys.exit(1)

# Hugging Face API token (ensure it's set in your environment)
api_token = os.getenv("HF_API_TOKEN")

# Hugging Face repo ID
repo_id = "Mungert/Phi-4-mini-instruct.gguf"

# Initialize API
api = HfApi()

# Loop through files passed as arguments and delete them
for file_to_delete in sys.argv[1:]:
    try:
        api.delete_file(path_in_repo=file_to_delete, repo_id=repo_id, token=api_token)
        print(f"Successfully deleted {file_to_delete} from {repo_id}.")
    except Exception as e:
        print(f"Error deleting {file_to_delete}: {e}")

