#!/bin/bash

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

# Set the name of your Go application
app_name="tdo_agent"

# Set the version number
version="v0.9.0"

# Set the output directory for release packages
release_dir="releases/$version"

# Create the release directory if it doesn't exist
mkdir -p "$release_dir"

# Create a source code tarball
source_tarball="$release_dir/${app_name}_${version}_source.tar.gz"
tar -czf "$source_tarball" --exclude="releases" --exclude="build" --exclude=".git" --exclude=".idea" --exclude="package_release.sh" .

# Set the target platforms
platforms=("linux/amd64" "linux/arm64")

# Iterate over the target platforms and create binary tarballs
for platform in "${platforms[@]}"; do
    # Split the platform string into OS and architecture
    IFS='/' read -r -a parts <<< "$platform"
    os="${parts[0]}"
    arch="${parts[1]}"    

    # Set the output file path for the binary tarball
    binary_tarball="$release_dir/${app_name}_${version}_${os}_${arch}.tar.gz"

    # Create the binary tarball
    tar -czf "$binary_tarball" -C "build/$version" "${app_name}_${os}_${arch}"
done

echo "Release packages created in $release_dir"
