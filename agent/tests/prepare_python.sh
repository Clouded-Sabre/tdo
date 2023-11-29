#!/bin/bash

# Install Python and pip
sudo apt-get update
sudo apt-get install -y python3 python3-pip

# Install virtualenv
pip3 install virtualenv

# Create and activate a virtual environment
python3 -m virtualenv venv
source venv/bin/activate

# Install required Python packages
pip install requests

# Display Python and pip versions
python --version
pip --version

# Run your Python script
python int_test.py
