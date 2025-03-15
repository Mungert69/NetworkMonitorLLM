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
def build_imatrix_url(model_name):
    """
    Build the URL for the .imatrix file using the model name and print the URL.
    """
    imatrix_url = f"{IMATRIX_BASE_URL}{model_name}-GGUF/resolve/main/{model_name}.imatrix"
    
    # Print the constructed URL for debugging purposes
    print(f"Constructed imatrix URL: {imatrix_url}")
    
    return imatrix_url

def download_imatrix(input_dir, model_name):
    # Define the full path to the .imatrix file
    imatrix_file = os.path.join(input_dir, f"{model_name}.imatrix")
    
    if not os.path.exists(imatrix_file):
        print(f"{imatrix_file} not found. Downloading...")
        
        # Build the URL for the imatrix file
        imatrix_url = build_imatrix_url(model_name)
        
        # Download the imatrix file
        try:
            urllib.request.urlretrieve(imatrix_url, imatrix_file)
            print(f"Successfully downloaded the .imatrix file to {imatrix_file}")
        except Exception as e:
            print(f"Failed to download the .imatrix file: {e}")
            raise FileNotFoundError(f"Failed to download the imatrix file: {e}")
    else:
        print(f"{imatrix_file} already exists. Skipping download.")
    
    return imatrix_file


def quantize_model(input_model, base_name):
    # Get the directory from the full input model path
    input_dir = os.path.dirname(input_model)  # Directory where the model is located
    output_dir = input_dir  # Keep output in the same folder
    
    # Construct paths for BF16 model and imatrix file based on the base model name
    bf16_model_file = os.path.join(input_dir, f"{base_name}-bf16.gguf")
    # Download the imatrix file if not already present
    imatrix_file = download_imatrix(input_dir, base_name)
     
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
    parser.add_argument("base_name", help="Base model name (without file extension, e.g., 'google/gemma-3-1b')")
    
    args = parser.parse_args()
    
    # Manually specify the full model directory path
    model_dir = os.path.join(os.getcwd(), args.base_name)  # Now points to the correct model directory
    
    # Quantize the model based on the provided base name
    quantize_model(os.path.join(model_dir, f"{args.base_name}-bf16.gguf"), args.base_name)

if __name__ == "__main__":
    main()

