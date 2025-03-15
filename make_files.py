import os
import subprocess
import argparse
import urllib.request
from update_readme import update_readme  # Importing the update_readme function

IMATRIX_BASE_URL = "https://huggingface.co/bartowski/"

QUANT_CONFIGS = [
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
    ("q4_0", "Q4_0", "Q8_0", "Q8_0", True, True),
    ("q4_1", "Q4_1", "Q8_0", "Q8_0", True, True),
]
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
    model_name_final = f"{first_part_company_name_cap}-{model_name_corrected}"

    # Step 4: Build the URLs
    return [
        f"{IMATRIX_BASE_URL}{model_name}-GGUF/resolve/main/{model_name}.imatrix",
        f"{IMATRIX_BASE_URL}{model_name_final}-GGUF/resolve/main/{model_name_final}.imatrix"
    ]

def download_imatrix(input_dir, company_name, model_name):
    """
    Attempt to download the .imatrix file from multiple possible locations.
    If download fails, generate it locally using llama-imatrix.
    """
    imatrix_file = os.path.join(input_dir, f"{model_name}.imatrix")
    
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
    
    for suffix, quant_type, tensor_type, embed_type, use_imatrix, use_pure in QUANT_CONFIGS:
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
