#!/bin/bash

#
# Copyright 2023 Rodger Wang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Set the target platforms
platforms=("linux/amd64" "linux/arm64")

# Set the version number
version="v0.9.0"

# Set the output directory
output_dir="build/$version"

# Set the name of your Go application
app_name="tdo_agent"

# Create the output directory if it doesn't exist
mkdir -p "$output_dir"

# Iterate over the target platforms and compile the binary
for platform in "${platforms[@]}"; do
    # Split the platform string into OS and architecture
    IFS='/' read -r -a parts <<< "$platform"
    os="${parts[0]}"
    arch="${parts[1]}"

    # Set environment variables for the current platform
    export GOOS="$os"
    export GOARCH="$arch"

    # Create the output file path
    output_file="$output_dir/${app_name}_${os}_${arch}"

    # Compile the binary
    go build -o "$output_file" .  

    # Check if the compilation was successful
    if [ $? -eq 0 ]; then
        echo "Binary compiled for $platform"
    else
        echo "Failed to compile binary for $platform"
    fi
done

# Reset environment variables to default values
export GOOS=""
export GOARCH=""

echo "Compilation complete"
