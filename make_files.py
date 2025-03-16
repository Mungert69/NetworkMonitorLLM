import os
import subprocess
import argparse
import urllib.request
from update_readme import update_readme  # Importing the update_readme function
import shutil

IMATRIX_BASE_URL = "https://huggingface.co/bartowski/"

QUANT_CONFIGS = [
    ("f16","F16","F16","F16",False,False),
    ("f16-q8_0", "Q8_0", "F16", "F16", False, False),
    ("bf16-q8_0", "Q8_0", "BF16", "BF16", False, False),
    ("f16-q6_k", "Q6_K", "F16", "F16", True, False),
    ("bf16-q6_k", "Q6_K", "BF16", "BF16", True, False),
    ("f16-q4_k", "Q4_K", "F16", "F16", True, False),
    ("bf16-q4_k", "Q4_K", "BF16", "BF16", True, False),
    ("q2_k_l", "Q2_K", "Q8_0", "Q8_0", True, False),
    ("q3_k_l", "Q3_K", "Q8_0", "Q8_0", True, False),
    ("q4_k_l", "Q4_K", "Q8_0", "Q8_0", True, False),
    ("q5_k_l", "Q5_K", "Q8_0", "Q8_0", True, False),
    ("q6_k_l", "Q6_K", "Q8_0", "Q8_0", True, False),
    ("q3_k_m", "Q3_K_M", None, None, True, False),
    ("q3_k_s", "Q3_K_S", None, None, True, False),
    ("q4_k_m", "Q4_K", None, None, True, False),
    ("q4_k_s", "Q4_K_S", None, None, True, False),
    ("q5_k_s", "Q5_K_S", None, None, True, False),
    ("q5_k_m", "Q5_K_M", None, None, True, False),
    ("q6_k_m", "Q6_K", None, None, True, False), 
    ("q8_0", "Q8_0", None, None, False, True), 
    ("iq4_xs", "IQ4_XS", None, None, True, False),
    ("iq3_xs", "IQ3_XS", None, None, True, False),
    ("iq4_nl", "IQ4_NL", None, None, True, False),
    ("q4_0", "Q4_0", None, None, True, True),
    ("q4_1", "Q4_1", None, None, True, True),
    ("q4_0_l", "Q4_0", "Q8_0", "Q8_0", True, True),
    ("q4_1_l", "Q4_1", "Q8_0", "Q8_0", True, True),
    ("q5_0", "Q5_0", None, None, True, True),
    ("q5_1", "Q5_1", None, None, True, True),
    ("q5_0_l", "Q5_0", "Q8_0", "Q8_0", True, True),
    ("q5_1_l", "Q5_1", "Q8_0", "Q8_0", True, True),
    ("iq2_xs", "IQ2_XS", None, None, True, False),
    ("iq2_xxs", "IQ2_XXS", None, None, True, False),
    ("iq2_s", "IQ2_S", None, None, True, False),
    ("iq2_m", "IQ2_M", None, None, True, False),
    ("iq1_s", "IQ1_S", None, None, True, False),
    ("iq1_m", "IQ1_M", None, None, True, False),
    ("tq1_0", "TQ1_0", None, None, True, False),
    ("tq2_0", "TQ2_0", None, None, True, False),
    ("q2_k_s", "Q2_K_S", None, None, True, False),
    ("iq3_xxs", "IQ3_XXS", None, None, True, False),
    ("iq3_s", "IQ3_S", None, None, True, False),
    ("iq3_m", "IQ3_M", None, None, True, False)
]
# Add this mapping at the top of your file
QUANT_BIT_LEVELS = {
    # 1-bit quantizations (very aggressive)
    "IQ1_S": 1, "IQ1_M": 1, 
    # 2-bit quantizations
    "Q2_K": 2, "Q2_K_S": 2, "Q2_K_M": 2, "IQ2_XS": 2, "IQ2_S": 2, "IQ2_M": 2, "IQ2_XXS": 2, 
    # 3-bit quantizations
    "Q3_K": 3, "Q3_K_S": 3, "Q3_K_M": 3, "IQ3_XS": 3, "IQ3_S": 3, "IQ3_M": 3, "IQ3_XXS": 3,
    # 4-bit and up
    "Q4_K": 4, "Q4_K_S": 4, "Q4_K_M": 4, "IQ4_XS": 4, "IQ4_NL": 4, "Q4_0": 4, "Q4_1": 4,
    "Q5_K": 5, "Q5_K_S": 5, "Q5_K_M": 5, "Q5_0": 5, "Q5_1" : 5,
    "Q6_K": 6, "Q8_0": 8, "F16": 16, "BF16": 16
}

def get_model_size(base_name):
    """Extract model size from name using common patterns for both billion and million sizes."""
    import re
    # Look for patterns like 7b, 13b, 1.8b, 3b, 70b, etc., and 1.2m, 10m, etc.
    match = re.search(r'(\d+\.?\d*)\s*([bm])', base_name, re.IGNORECASE)
    if match:
        size = float(match.group(1))
        size_unit = match.group(2).lower()

        if size_unit == 'b':  # Billion
            return size * 1e9
        elif size_unit == 'm':  # Million
            return size * 1e6
    return None

def filter_quant_configs(base_name, configs):
    """Filter quantization configs based on model size, adding TQ quants if 'TriLM' is in the name."""
    model_size = get_model_size(base_name)
    
    if not model_size:
        print("⚠ Couldn't determine model size from name. Using all quantizations.")
        return configs

    # Set minimum bit levels based on model size
    min_bits = 3 if model_size < 3e9 else (  # <3B models
                2 if model_size < 7e9 else   # 3-7B models
                1)                           # 7B+ models

    filtered = []
    for config in configs:
        quant_type = config[1]
        bits = QUANT_BIT_LEVELS.get(quant_type, 16)
        
        if bits >= min_bits or ("TriLM" in base_name and quant_type.startswith("TQ")):
            filtered.append(config)
        else:
            print(f"⚠ Skipping {quant_type} ({bits}bit) for {base_name} "
                  f"({model_size/1e9:.1f}B) - too aggressive")

    return filtered

IMATRIX_BASE_URL = "https://huggingface.co/bartowski/"

def build_imatrix_urls(company_name, model_name):
    """
    Build possible URLs for the .imatrix file using the company name and model name.
    """
    # Step 1: Split and capitalize the company name, use only the first part
    company_name_parts = company_name.split("-")
    first_part_company_name_cap = company_name_parts[0].capitalize()  # Only capitalize the first part
    
    # Step 2: Remove the second part of the company name from the start of the model name
    model_name_parts = model_name.split("-")
    
    # Check if the model name starts with the capitalized first part of the company name
    if model_name_parts[0] == first_part_company_name_cap:
        # Remove the first part of the company name from the model name
        model_name_corrected = "-".join(model_name_parts[1:])
    else:
        # No need to modify the model name
        model_name_corrected = model_name
    
    # Step 3: Rebuild the model name using only the first part of the company name
    model_name_1 = f"{first_part_company_name_cap}-{model_name_corrected}"
    model_name_2 = f"{company_name}_{model_name}"
    # Step 4: Build the URLs
    return [
        f"{IMATRIX_BASE_URL}{model_name}-GGUF/resolve/main/{model_name}.imatrix",
        f"{IMATRIX_BASE_URL}{model_name_1}-GGUF/resolve/main/{model_name_1}.imatrix",
        f"{IMATRIX_BASE_URL}{model_name_2}-GGUF/resolve/main/{model_name_2}.imatrix"
    ]

def download_imatrix(input_dir, company_name, model_name):
    """
    Attempt to download the .imatrix file from multiple possible locations.
    If download fails, generate it locally using llama-imatrix.
    Save the generated imatrix file in both the model's folder and the 'imatrix-files' directory.
    First, check if the imatrix file already exists in the 'imatrix-files' directory.
    """
    # Define the paths for the imatrix file
    imatrix_dir = os.path.join(input_dir, "imatrix-files")  # New directory for imatrix files
    imatrix_file_copy = os.path.join(imatrix_dir, f"{model_name}.imatrix")  # Copy location
    imatrix_file = os.path.join(input_dir, f"{model_name}.imatrix")  # Original location
    
    # Step 1: Check if the imatrix file already exists in the 'imatrix-files' directory
    if os.path.exists(imatrix_file_copy):
        print(f"Found existing .imatrix file in 'imatrix-files' directory: {imatrix_file_copy}")
        # Copy the file to the model's folder for use
        shutil.copy(imatrix_file_copy, imatrix_file)
        print(f"Copied .imatrix file to model's folder: {imatrix_file}")
        return imatrix_file
    
    print(f"DEBUG: Checking for .imatrix file in directory: {input_dir}")
    print(f"DEBUG: Expected .imatrix file path: {imatrix_file}")
    
    if not os.path.exists(imatrix_file):
        print(f"{imatrix_file} not found. Attempting to download...")

        urls = build_imatrix_urls(company_name, model_name)
        
        print("DEBUG: Trying the following URLs for .imatrix file:")
        for url in urls:
            print(f" - {url}")

        downloaded = False
        for url in urls:
            try:
                print(f"Trying: {url}")
                urllib.request.urlretrieve(url, imatrix_file)
                print(f"Successfully downloaded .imatrix from {url}")
                downloaded = True
                break
            except Exception as e:
                print(f"Failed to download from {url}: {e}")

        if not downloaded:
            print("All download attempts failed. Generating imatrix locally...")
            # Path to the BF16 model required for imatrix generation
            bf16_model_path = os.path.join(input_dir, f"{model_name}-bf16.gguf")
            if not os.path.exists(bf16_model_path):
                raise FileNotFoundError(f"Cannot generate imatrix: {bf16_model_path} not found")

            # Path to training data - update this if needed
            imatrix_train_set = "imatrix-train-set"  # Change this to your training data path
            
            command = [
                "./llama.cpp/llama-imatrix",
                "-m", bf16_model_path,
                "-f", imatrix_train_set,
                "-o", imatrix_file
            ]
            
            print("Running:", " ".join(command))
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                print("Error generating imatrix:")
                print(result.stderr)
                raise RuntimeError("Failed to generate imatrix file")
            else:
                print("Successfully generated imatrix file")
                
                # Save a copy of the imatrix file in the 'imatrix-files' directory
                os.makedirs(imatrix_dir, exist_ok=True)  # Create the directory if it doesn't exist
                shutil.copy(imatrix_file, imatrix_file_copy)
                print(f"Saved a copy of the imatrix file to: {imatrix_file_copy}")
    
    else:
        print(f"{imatrix_file} already exists. Skipping download.")
    
    return imatrix_file

def quantize_model(input_model, company_name, base_name):
    # Get the directory from the full input model path
    input_dir = os.path.dirname(input_model)  # Directory where the model is located
    output_dir = input_dir  # Keep output in the same folder
    
    # Construct paths for BF16 model and imatrix file based on the base model name
    bf16_model_file = os.path.join(input_dir, f"{base_name}-bf16.gguf")
    # Download the imatrix file if not already present
    imatrix_file = download_imatrix(input_dir, company_name, base_name)

    if not os.path.exists(bf16_model_file):
        raise FileNotFoundError(f"BF16 model not found: {bf16_model_file}")
    
    os.makedirs(output_dir, exist_ok=True)  # Ensure output directory exists
    # Get filtered configs based on model size
    filtered_configs = filter_quant_configs(base_name, QUANT_CONFIGS)
    
    print(f"🏗️ Selected {len(filtered_configs)} quantizations for {base_name}")
    
    for suffix, quant_type, tensor_type, embed_type, use_imatrix, use_pure in filtered_configs:
        output_file = f"{base_name}-{suffix}.gguf"
        output_path = os.path.join(output_dir, output_file)
        
        command = ["./llama.cpp/llama-quantize"]
        
        if use_imatrix:
            command.extend(["--imatrix", imatrix_file])
            
        if use_pure:
            command.append("--pure")
            
        if tensor_type and embed_type:
            command.extend(["--output-tensor-type", tensor_type])
            command.extend(["--token-embedding-type", embed_type])
            
        command.extend([bf16_model_file, output_path, quant_type])
        
        print("\nRunning:", " ".join(command))
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Successfully created {output_file} in {output_dir}")
        else:
            print(f"Error creating {output_file}:")
            print(result.stderr)
  # After quantization, update the README.md
    update_readme(output_dir, base_name)  # This updates the README with the new information


def main():
    parser = argparse.ArgumentParser(description="Automate GGUF model quantization")
    parser.add_argument("model_id", help="Full Hugging Face model ID (e.g., 'company/model')")
    
    args = parser.parse_args()

    # Extract company_name and model_name from model_id
    if "/" not in args.model_id:
        print("Error: Model ID must be in the format 'company_name/model_name'.")
        exit(1)

    company_name, model_name = args.model_id.split("/", 1)

    model_dir = os.path.join(os.getcwd(), model_name)

    quantize_model(os.path.join(model_dir, f"{model_name}-bf16.gguf"), company_name, model_name)

if __name__ == "__main__":
    main()
