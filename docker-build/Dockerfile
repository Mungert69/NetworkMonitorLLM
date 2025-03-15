# Use the official Ubuntu 24.04 base image
FROM ubuntu:24.04

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt update && \
    apt upgrade -y && \
    apt-get install -y build-essential git cmake clang pkg-config ccache wget vim

# Install .NET 9.0
RUN wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh && \
    chmod +x dotnet-install.sh && \
    ./dotnet-install.sh --channel 9.0 && \
    export DOTNET_ROOT=/root/.dotnet && \
    export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools && \
    echo 'export DOTNET_ROOT=/root/.dotnet' >> /root/.bashrc && \
    echo 'export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools' >> /root/.bashrc

# Install CUDA Toolkit and Libraries
RUN wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-ubuntu2404.pin && \
    mv cuda-ubuntu2404.pin /etc/apt/preferences.d/cuda-repository-pin-600 && \
    wget https://developer.download.nvidia.com/compute/cuda/12.8.0/local_installers/cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb && \
    dpkg -i cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb && \
    cp /var/cuda-repo-ubuntu2404-12-8-local/cuda-*-keyring.gpg /usr/share/keyrings/ && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        cuda-toolkit-12-8 \
        cuda-libraries-12-8 \
        cuda-libraries-dev-12-8 && \
    rm -rf /var/lib/apt/lists/*

# Set the library path and CUDA environment variables
ENV CUDA_HOME=/usr/local/cuda-12.8
ENV PATH=${CUDA_HOME}/bin:${PATH}
ENV LD_LIBRARY_PATH=${CUDA_HOME}/lib64

# Clone repositories
RUN mkdir -p /root/code && \
    cd /root/code && \
    git clone https://mungert69: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@github.com/Mungert69/NetworkMonitor.git && \
    git clone https://mungert69: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@github.com/Mungert69/NetworkMonitorLLM.git && \
    git clone https://mungert69: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@github.com/Mungert69/NetworkMonitorData.git

# Copy files into the container
COPY system_prompt_phi_4_mini /root/code/models/system_prompt_phi_4_mini
COPY appsettings.json /root/code/NetworkMonitorLLM/appsettings.json
COPY append_run.sh /root/code/models/append_run.sh
COPY build-phi-4-mini /root/code/models/build-phi-4-mini

# Set permissions for scripts
RUN chmod +x /root/code/models/append_run.sh

# Build llama.cpp with CUDA support
RUN ln -s /usr/local/cuda-12.8/targets/x86_64-linux/lib/stubs/libcuda.so /usr/local/cuda-12.8/targets/x86_64-linux/lib/stubs/libcuda.so.1 && \
    mkdir -p /root/code && \
    cd /root/code && \
    git clone https://github.com/ggerganov/llama.cpp && \
    cd llama.cpp && \
    cmake -B build -DGGML_CUDA=ON \
        -DCMAKE_CUDA_COMPILER=${CUDA_HOME}/bin/nvcc \
        -DCUDAToolkit_ROOT=${CUDA_HOME} \
        -DCMAKE_CUDA_ARCHITECTURES=75 && \
    cmake --build build --config Release

# Download the Phi-4-mini model
RUN mkdir -p /root/code/models && \
    cd /root/code/models && \
    wget https://huggingface.co/Mungert/Phi-4-mini-instruct.gguf/resolve/main/phi-4-mini-q4_k_l.gguf

# Set the working directory
WORKDIR /root/code

# Default command (can be overridden at runtime)
CMD ["bash"]
