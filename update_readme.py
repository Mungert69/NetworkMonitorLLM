import os

# Function to update the README.md file with the new section
def update_readme(model_dir, base_name):
    readme_file = os.path.join(model_dir, "README.md")
    
    # Check if README.md exists
    if not os.path.exists(readme_file):
        raise FileNotFoundError(f"README.md not found in {model_dir}")
    
    # Read the existing content of the README.md
    with open(readme_file, "r") as file:
        readme_content = file.read()
    
    # Find where the metadata section ends (find the second occurrence of '---')
    meta_end = readme_content.find("---", readme_content.find("---") + 3) + 3  # Locate second '---'
    
    # The new content to be added after the metadata section
    new_section = f"""

# <span style="color: #7FFF7F;">{base_name} GGUF Models</span>

## **Choosing the Right Model Format**  

Selecting the correct model format depends on your **hardware capabilities** and **memory constraints**.  

### **BF16 (Brain Float 16) – Use if BF16 acceleration is available**  
- A 16-bit floating-point format designed for **faster computation** while retaining good precision.  
- Provides **similar dynamic range** as FP32 but with **lower memory usage**.  
- Recommended if your hardware supports **BF16 acceleration** (check your device’s specs).  
- Ideal for **high-performance inference** with **reduced memory footprint** compared to FP32.  

📌 **Use BF16 if:**  
✔ Your hardware has native **BF16 support** (e.g., newer GPUs, TPUs).  
✔ You want **higher precision** while saving memory.  
✔ You plan to **requantize** the model into another format.  

📌 **Avoid BF16 if:**  
❌ Your hardware does **not** support BF16 (it may fall back to FP32 and run slower).  
❌ You need compatibility with older devices that lack BF16 optimization.  

---

### **F16 (Float 16) – More widely supported than BF16**  
- A 16-bit floating-point **high precision** but with less of range of values than BF16. 
- Works on most devices with **FP16 acceleration support** (including many GPUs and some CPUs).  
- Slightly lower numerical precision than BF16 but generally sufficient for inference.  

📌 **Use F16 if:**  
✔ Your hardware supports **FP16** but **not BF16**.  
✔ You need a **balance between speed, memory usage, and accuracy**.  
✔ You are running on a **GPU** or another device optimized for FP16 computations.  

📌 **Avoid F16 if:**  
❌ Your device lacks **native FP16 support** (it may run slower than expected).  
❌ You have memory limitations.  

---

### **Quantized Models (Q4_K, Q6_K, Q8, etc.) – For CPU & Low-VRAM Inference**  
Quantization reduces model size and memory usage while maintaining as much accuracy as possible.  
- **Lower-bit models (Q4_K)** → **Best for minimal memory usage**, may have lower precision.  
- **Higher-bit models (Q6_K, Q8_0)** → **Better accuracy**, requires more memory.  

📌 **Use Quantized Models if:**  
✔ You are running inference on a **CPU** and need an optimized model.  
✔ Your device has **low VRAM** and cannot load full-precision models.  
✔ You want to reduce **memory footprint** while keeping reasonable accuracy.  

📌 **Avoid Quantized Models if:**  
❌ You need **maximum accuracy** (full-precision models are better for this).  
❌ Your hardware has enough VRAM for higher-precision formats (BF16/F16).  

---

### **Summary Table: Model Format Selection**  

| Model Format  | Precision  | Memory Usage  | Device Requirements  | Best Use Case  |  
|--------------|------------|---------------|----------------------|---------------|  
| **BF16**     | Highest       | High      | BF16-supported GPU/CPUs  | High-speed inference with reduced memory |  
| **F16**      | High     | High           | FP16-supported devices | GPU inference when BF16 isn’t available |  
| **Q4_K**     | Low        | Very Low      | CPU or Low-VRAM devices | Best for memory-constrained environments |  
| **Q6_K**     | Medium Low     | Low      | CPU with more memory | Better accuracy while still being quantized |  
| **Q8**       | Medium       | Moderate        | CPU or GPU with enough VRAM | Best accuracy among quantized models |  


## **Included Files & Details**  

### `{base_name}-bf16.gguf`  
- Model weights preserved in **BF16**.  
- Use this if you want to **requantize** the model into a different format.  
- Best if your device supports **BF16 acceleration**.  

### `{base_name}-f16.gguf`  
- Model weights stored in **F16**.  
- Use if your device supports **FP16**, especially if BF16 is not available.  

### `{base_name}-bf16-q8_0.gguf`  
- **Output & embeddings** remain in **BF16**.  
- All other layers quantized to **Q8_0**.  
- Use if your device supports **BF16** and you want a quantized version.  

### `{base_name}-f16-q8_0.gguf`  
- **Output & embeddings** remain in **F16**.  
- All other layers quantized to **Q8_0**.    

### `{base_name}-q4_k.gguf`  
- **Output & embeddings** quantized to **Q8_0**.  
- All other layers quantized to **Q4_K**.  
- Good for **CPU inference** with limited memory.  

### `{base_name}-q4_k_s.gguf`  
- Smallest **Q4_K** variant, using less memory at the cost of accuracy.  
- Best for **very low-memory setups**.  

### `{base_name}-q6_k.gguf`  
- **Output & embeddings** quantized to **Q8_0**.  
- All other layers quantized to **Q6_K** .  


### `{base_name}-q8_0.gguf`  
- Fully **Q8** quantized model for better accuracy.  
- Requires **more memory** but offers higher precision

# <span id="testllm" style="color: #7F7FFF;">🚀 If you find these models useful</span>

Please click like ❤ . Also I’d really appreciate it if you could test my Network Monitor Assistant at 👉 [Network Monitor Assitant](https://freenetworkmonitor.click/dashboard).

💬 Click the **chat icon** (bottom right of the main and dashboard pages) . Choose a LLM; toggle between the LLM Types TurboLLM -> FreeLLM -> TestLLM.

### What I'm Testing

I'm experimenting with **function calling** against my network monitoring service. Using small open source models. I am into the question "How small can it go and still function".

🟡 **TestLLM** – Runs the current testing model using llama.cpp on 6 threads of a Cpu VM (Should take about 15s to load. Inference speed is quite slow and it only processes one user prompt at a time—still working on scaling!). If you're curious, I'd be happy to share how it works! .

### The other Available AI Assistants

🟢 **TurboLLM** – Uses **gpt-4o-mini** Fast! . Note: tokens are limited since OpenAI models are pricey, but you can [Login](https://freenetworkmonitor.click) or [Download](https://freenetworkmonitor.click/download) the Free Network Monitor agent to get more tokens, Alternatively use the FreeLLM .

🔵 **FreeLLM** – Runs **open-source Hugging Face models** Medium speed (unlimited, subject to Hugging Face API availability).


"""

    # Update the README.md content
    updated_content = readme_content[:meta_end] + new_section + readme_content[meta_end:]
    
    # Write the updated content back to the README.md
    with open(readme_file, "w") as file:
        file.write(updated_content)

    print(f"README.md updated successfully for {base_name}.")

# Main function for quantization
def quantize_model(model_path, output_dir, base_name):
    print("Starting quantization process...")

    # Here you should include your existing quantization logic
    # For example:
    # - Load the model
    # - Apply quantization
    # - Save the quantized models in the output_dir

    # Example (replace with actual quantization logic):
    # quantized_model = apply_quantization(model_path)
    # save_model(quantized_model, output_dir)
    
    # After quantization, update the README.md
    update_readme(output_dir, base_name)

# Example usage
if __name__ == "__main__":
    model_path = "/path/to/your/model"  # Replace with the model path
    output_dir = "/path/to/output/folder"  # Replace with the output directory path
    base_name = "Gemma-3-1B-Instruct"  # Replace with the base name of the model
    quantize_model(model_path, output_dir, base_name)

