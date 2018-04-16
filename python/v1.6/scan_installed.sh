#!/bin/bash

# Get list of installed packages and versions, and save CSV

# Get list of installed packages and versions
apt list --installed | sed -n '1!p' | sed 's/ /, /g' > installed.txt

# Get device name
dmidecode | grep -A3 '^System Information' | grep 'Product Name' | cut -d: -f2- | tr -d ' ' > vendor_version_linux.txt

# Get OS version
lsb_release -a | grep 'Description' | cut -d: -f2- | sed 's/[^a-zA-Z0-9]//g' > linux_ver.txt

# Save to CSV
python cleanup.py

# Cleanup
rm installed.txt


