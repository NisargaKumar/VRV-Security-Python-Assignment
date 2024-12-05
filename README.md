# VRV Security Python Assignment

This project analyzes log files to detect suspicious activities, track IP request counts, and identify the most accessed endpoints. It is designed to help monitor security in real-time by processing log files and providing insights.

## Features:
- **IP Request Count**: Tracks the number of requests made by each IP address.
- **Most Accessed Endpoint**: Identifies which endpoint was accessed the most.
- **Suspicious Activity Detection**: Detects potential brute force attacks by identifying IPs with multiple failed login attempts.

## Setup

To get started with this project, follow these steps to set up your environment and run the code.

# 1. Clone the Repository  
git clone https://github.com/NisargaKumar/VRV-Security-Python-Assignment.git  

# 2. Set Up a Virtual Environment  
# Create a virtual environment to isolate dependencies:   
# On Windows  
python -m venv venv  

# On macOS/Linux  
python3 -m venv venv  
  
# Activate the virtual environment:  
# On Windows   
venv\Scripts\activate  

# On macOS/Linux  
source venv/bin/activate   

# 3. Install Dependencies  

# This project uses built-in Python libraries (re, csv, collections),  
# so you don't need to install any additional packages.  

# 4. Run the Code  
python log_analysis.py  
