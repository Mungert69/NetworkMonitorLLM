import subprocess
import sys
import json
import os
import shutil

def run_script(script_name, args):
    """Runs a script with arguments and checks for success."""
    script_path = os.path.join(os.getcwd(), script_name)  # Ensure absolute path
    if not os.path.exists(script_path):
        print(f"Error: Script {script_name} not found at {script_path}")
        sys.exit(1)

    print(f"Running {script_name} with arguments: {args}")
    result = subprocess.run(["python3", script_path] + args, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error running {script_name}: {result.stderr}")
        sys.exit(1)
    else:
        print(f"Successfully ran {script_name}")

def cleanup_model_dir(model_name):
    """Clean up the model directory to free up disk space."""
    model_dir = os.path.join("./", model_name)  # Directly use model's folder name
    
    if os.path.exists(model_dir):
        print(f"Cleaning up directory: {model_dir}")
        shutil.rmtree(model_dir)  # Remove the entire directory and its contents
        print(f"Successfully cleaned up {model_dir}")
    else:
        print(f"Directory {model_dir} not found, skipping cleanup.")

def process_model(model_id):
    """Process a single model: download, convert, quantize, and upload."""
    print(f"\nProcessing model: {model_id}")

    # Extract model name (folder)
    model_name = model_id.split("/")[-1]  

    # 1. Download and Convert (download_convert.py)
    download_convert_args = [model_id, model_name]  # Store in model_name directory
    run_script("download_convert.py", download_convert_args)

    # 2. Quantize model (make_files.py)
    make_files_args = [model_name]
    run_script("make_files.py", make_files_args)

    # 3. Upload files (upload-files.py)
    upload_files_args = [model_name]
    run_script("upload-files.py", upload_files_args)

    # Cleanup after processing this model
    cleanup_model_dir(model_name)

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_all_from_json.py <path_to_models_json>")
        sys.exit(1)

    json_file = sys.argv[1]

    try:
        with open(json_file, "r") as f:
            data = json.load(f)
            model_ids = data.get("models", [])
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)

    if not model_ids:
        print("No model IDs found in the JSON file.")
        sys.exit(1)

    for model_id in model_ids:
        process_model(model_id)

    print("All models processed successfully.")

if __name__ == "__main__":
    main()

