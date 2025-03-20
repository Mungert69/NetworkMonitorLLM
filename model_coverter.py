import os
import json
import time
import requests
from datetime import datetime
from run_all_from_json import run_script  # Import the run_script function
from dotenv import load_dotenv
from make_files import get_model_size  # Import get_model_size from make_files.py
from huggingface_hub import HfApi, HfFileSystem, login  # Import for authentication
from build_llama import build_and_copy

load_dotenv()  # Load environment variables

class ModelConverter:
    def __init__(self):
        self.catalog_file = "model_catalog.json"
        self.catalog = self.load_catalog()
        self.hf_token = os.getenv("HF_API_TOKEN")
        self.MAX_PARAMETERS = 20e9  # 20 billion parameters
        
        # Authenticate with Hugging Face Hub
        if not self.hf_token:
            print("Error: Hugging Face API token not found in .env file.")
            exit()
        try:
            login(token=self.hf_token)
            print("Authentication successful.")
        except Exception as e:
            print(f"Authentication failed: {e}")
            exit()
        
        self.api = HfApi()  # Initialize API client
        self.fs = HfFileSystem()  # Initialize File System client
    
    def get_file_sizes(self, model_id):
        """Get the total size of .safetensors files in the repository as a fallback for parameter estimation."""
        try:
            print(f"Checking file sizes in repository: {model_id}")  # Debug logging
            
            # Fix repository path from datasets to models
            files = self.fs.ls(f'models/{model_id}', detail=True)
            
            # Filter for .safetensors files and calculate their total size
            safetensors_files = [file for file in files if file['name'].endswith('.safetensors')]
            if not safetensors_files:
                print(f"Warning: No .safetensors files found for {model_id}")
                return 0  # Avoid returning None

            total_size = sum(file['size'] for file in safetensors_files)
            
            print(f"Found {len(safetensors_files)} .safetensors files with total size: {total_size} bytes")
            return total_size
        except Exception as e:
            print(f"Error retrieving file sizes for {model_id}: {e}")
            return 0

    def estimate_parameters(self, file_size):
        """Estimate the number of parameters based on file size."""
        if file_size == 0:
            return 0  # Ensure zero instead of None

        # Handling both float32 (4 bytes) and bfloat16/float16 (2 bytes)
        estimated_params_fp32 = file_size / 4
        estimated_params_fp16 = file_size / 2  # If model uses bfloat16 or float16

        print(f"Estimated parameters (FP32): {estimated_params_fp32}, (FP16/BF16): {estimated_params_fp16}")

        # Use FP32 estimation by default, but FP16/BF16 if model is known to use it
        return estimated_params_fp32  

    def load_catalog(self):
        try:
            with open(self.catalog_file, "r") as f:
                catalog = json.load(f)
                
                # Ensure has_config field exists
                for model_id, entry in catalog.items():
                    if "has_config" not in entry:
                        entry["has_config"] = self.has_config_json(model_id)
                        
                return catalog
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
            
    def save_catalog(self):
        with open(self.catalog_file, "w") as f:
            json.dump(self.catalog, f, indent=2)

    def get_trending_models(self, limit=50):
        """Fetch trending models from Hugging Face API"""
        url = "https://huggingface.co/api/models"
        params = {"limit": limit}
        
        try:
            print(f"Making API request to: {url} with params: {params}")  # Debug logging
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching models: {e}")
            return []

    def has_config_json(self, model_id):
        """Check if the repository has a config.json file"""
        try:
            files = self.api.list_repo_files(model_id)
            return "config.json" in files
        except Exception as e:
            print(f"Error checking config.json for {model_id}: {e}")
            return False
    def update_catalog(self, models):
        """Add new models to catalog if they don't exist"""
        for model in models:
            model_id = model['modelId']
            print(f"Processing model: {model_id}")  # Debugging log
            
            if not self.has_config_json(model_id):
                print(f"Skipping {model_id} - config.json not found")
                continue
            
            if model_id not in self.catalog:
                parameters = model.get('config', {}).get('num_parameters')

                if parameters is None:
                    base_name = model_id.split('/')[-1]
                    parameters = get_model_size(base_name)  # From make_files.py
                
                if parameters is None or parameters == 0:
                    print(f"Estimating parameters via file size for {model_id}")
                    total_size = self.get_file_sizes(model_id)
                    if total_size > 0:
                        parameters = self.estimate_parameters(total_size)

                if parameters is None or parameters == 0:
                    print(f"Warning: {model_id} parameters could not be determined, setting to -1 as a flag.")
                    parameters = -1  # Set to -1 to flag that parameter estimation failed.

                if parameters > self.MAX_PARAMETERS:
                    print(f"Skipping {model_id} - {parameters} parameters exceed limit.")
                    continue
                
                print(f"Adding {model_id} with parameters={parameters}")
                self.catalog[model_id] = {
                    "added": datetime.now().isoformat(),
                    "parameters": parameters,
                    "has_config": True,
                    "converted": False,
                    "attempts": 0,
                    "last_attempt": None,
                    "success_date": None,
                    "error_log": [],
                    "quantizations": []
                }
        
        self.save_catalog()

    def convert_model(self, model_id):
        """Run conversion pipeline using the run_script function"""
        entry = self.catalog[model_id]
        entry["attempts"] += 1
        entry["last_attempt"] = datetime.now().isoformat()
        self.save_catalog()

        success = True  # Assume success initially

        try:
            print(f"Converting {model_id}...")

            # Run each script and check for success
            scripts = [
                ("download_convert.py", [model_id, model_id.split('/')[-1]]),
                ("make_files.py", [model_id]),
                ("upload-files.py", [model_id.split('/')[-1]])
            ]

            for script_name, script_args in scripts:
                print(f"Running {script_name}...")
                if not run_script(script_name, script_args):
                    print(f"Script {script_name} failed.")
                    success = False
                    break  # Stop further execution if any script fails

            if success:
                # Only mark as converted if all scripts succeeded
                entry["converted"] = True
                entry["success_date"] = datetime.now().isoformat()
                entry["error_log"] = []
                print(f"Successfully converted {model_id}.")
            else:
                print(f"Conversion failed for {model_id} due to script errors.")

        except Exception as e:
            entry["error_log"].append(str(e))
            print(f"Conversion failed for {model_id}: {e}")
        finally:
            self.save_catalog()


    def run_conversion_cycle(self):
        """Process all unconverted models"""
        models = self.get_trending_models()
        self.update_catalog(models)

        for model_id, entry in self.catalog.items():
            parameters = entry.get("parameters", 0) or 0 # Ensure parameters is never None
            if entry["converted"] or entry["attempts"] >= 3 or parameters > self.MAX_PARAMETERS:
                continue
                
            if not entry["has_config"]:
                print(f"Skipping {model_id} - config.json not found")
                continue
                
            self.convert_model(model_id)

    def start_daemon(self):
        """Run continuously with 15 minute intervals"""
        while True:
            print("Starting conversion cycle...")
            self.run_conversion_cycle()
            print("Cycle complete. Sleeping for 15 minutes...")
            time.sleep(9)  # 15 minutes

            # Call build_and_copy after each sleep
            print("Updating and rebuilding llama.cpp...")
            if not build_and_copy():
                print("Warning: Failed to update or rebuild llama.cpp")

if __name__ == "__main__":
    converter = ModelConverter()
    converter.start_daemon()

