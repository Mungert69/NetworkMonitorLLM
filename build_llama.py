import subprocess
import os
import shutil
import sys

# Define the paths and commands
llama_cpp_dir = "./llama.cpp"
build_dir = os.path.join(llama_cpp_dir, "build")
bin_dir = os.path.join(build_dir, "bin")

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
    """Build llama.cpp and copy binaries to the root directory."""
    try:
        # Git pull to get the latest changes
        print("Pulling latest changes from the repository...")
        run_command(["git", "pull"], cwd=llama_cpp_dir)

        # Run CMake to configure the build
        print("Configuring the build with CMake...")
        run_command(cmake_command, cwd=llama_cpp_dir)

        # Build the project
        print("Building the project...")
        run_command(build_command + [str(os.cpu_count())], cwd=llama_cpp_dir)

        # Copy binaries from build/bin to the root llama.cpp directory
        print("Copying binaries...")
        copy_binaries(bin_dir, llama_cpp_dir)

        print("Build and copy completed successfully!")
        return True

    except Exception as e:
        print(f"An error occurred: {e}")
        return False

if __name__ == "__main__":
    # When run as a script, execute the build_and_copy function
    success = build_and_copy()
    sys.exit(0 if success else 1)
