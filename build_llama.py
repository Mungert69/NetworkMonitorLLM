import subprocess
import os
import shutil
import sys

# Define paths
llama_cpp_dir = "./llama.cpp"
build_dir = os.path.join(llama_cpp_dir, "build")
bin_dir = os.path.join(build_dir, "bin")
patch_file = os.path.abspath("my_quant_changes.patch")  # Path to your patch file

# CMake and build commands
cmake_command = [
    "cmake", "-B", build_dir,
    "-DGGML_BLAS=ON",
    "-DGGML_BLAS_VENDOR=OpenBLAS",
    "-DBLAS_INCLUDE_DIRS=~/code/models/OpenBLAS"
]
build_command = ["cmake", "--build", build_dir, "--config", "Release", "-j"]

def run_command(command, cwd=None):
    """Run a shell command in the specified directory."""
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Command failed with return code {process.returncode}")
        print(f"STDOUT: {stdout}")
        print(f"STDERR: {stderr}")
        raise RuntimeError(f"Command failed with return code {process.returncode}")
    return stdout

def apply_patch():
    """Apply the patch file with fuzzy matching and fallback checks."""
    try:
        # Attempt standard patch application
        print("Applying custom quantization patch...")
        run_command(["git", "apply", "--ignore-space-change", "--ignore-whitespace", patch_file], cwd=llama_cpp_dir)
        return True
    
    except RuntimeError:
        # Check if the TARGET CODE still exists (even if line numbers changed)
        print("Patch failed. Checking if target code exists for manual retry...")
        grep_cmd = ["grep", "-q", "if (qs.i_ffn_down < qs.n_ffn_down/8", "src/llama-quant.cpp"]
        grep_process = subprocess.Popen(grep_cmd, cwd=llama_cpp_dir, stderr=subprocess.PIPE)
        grep_process.communicate()
        
        if grep_process.returncode == 0:
            # Original code exists -> line numbers likely changed
            print("Original code found. Retrying with 3-way merge...")
            try:
                run_command(["git", "apply", "-3", patch_file], cwd=llama_cpp_dir)
                return True
            except RuntimeError:
                print("3-way merge failed. Manual intervention required.")
                return False
        else:
            # Target code has been modified upstream
            print("CRITICAL: Target code has changed in llama-quant.cpp. Patch is outdated. Reapply with git diff -U10 --no-prefix > my_quant_changes.patch")
            return False

def copy_binaries(source_dir, destination_dir):
    """Copy all files from source_dir to destination_dir."""
    if not os.path.exists(source_dir):
        raise FileNotFoundError(f"Source directory {source_dir} does not exist.")
    
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
    
    for filename in os.listdir(source_dir):
        source_file = os.path.join(source_dir, filename)
        destination_file = os.path.join(destination_dir, filename)
        if os.path.isfile(source_file):
            print(f"Copying {filename} to {destination_dir}...")
            shutil.copy2(source_file, destination_file)

def build_and_copy():
    """Build llama.cpp with custom patch and copy binaries."""
    try:
        # Git pull to get latest changes
        print("Pulling latest changes from the repository...")
        run_command(["git", "pull"], cwd=llama_cpp_dir)

        # Apply custom patch
        if not apply_patch():
            raise RuntimeError("Patch application failed. Build aborted.")

        # Configure and build
        print("Configuring the build with CMake...")
        run_command(cmake_command, cwd=llama_cpp_dir)

        print("Building the project...")
        run_command(build_command + [str(os.cpu_count())], cwd=llama_cpp_dir)

        # Copy binaries
        print("Copying binaries...")
        copy_binaries(bin_dir, llama_cpp_dir)

        print("Build and copy completed successfully!")
        return True

    except Exception as e:
        print(f"An error occurred: {e}")
        return False

if __name__ == "__main__":
    success = build_and_copy()
    sys.exit(0 if success else 1)
