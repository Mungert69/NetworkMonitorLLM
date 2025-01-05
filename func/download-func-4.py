from huggingface_hub import hf_hub_download, list_repo_files

# Specify the model repository
repo_id = "meetkai/functionary-v4r-small-preview"

# List all files in the repository
files = list_repo_files(repo_id=repo_id)

# Download each file
for file_name in files:
    print(f"Downloading {file_name}...")
    try:
        file_path = hf_hub_download(repo_id=repo_id, filename=file_name)
        print(f"Downloaded {file_name} to {file_path}")
    except Exception as e:
        print(f"Failed to download {file_name}: {e}")

