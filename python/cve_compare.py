'''
CVE Compare
Version 1.2

Functionality:
Scans software in Windows and compares against the
NIST Vulnerability Database (NVD) to identify present vulnerabilities.
Includes optional scan for Microsoft hotfixes and patches.

Identifies:
    * Vendor Name
    * Vulnerable Software
    * Software Version
    * CVE Name
    * CVSS V3 Base Severity
    * CVE Description

Hotfix/Patch Scan Identifies:
    * Missing KBs as per identified vulnerabilities
    * Missing KBs as per last applied hotfix date
'''

import subprocess, sys, os
from datetime import datetime
from pathlib import Path
import requests
import zipfile
import json
import numpy as np
import pandas as pd


'''
Check whether a file already exists.
'''
def check_existence(filename):
    the_file = Path(filename)
    if the_file.is_file():
        return True


'''
Download a file.
'''
def download_file(url, filename):
    req = requests.get(url, stream=True)
    with open(filename, "wb") as f:
        for chunk in req.iter_content():
            f.write(chunk)


'''
Unzip a file.
'''
def unzip(filename):
    with zipfile.ZipFile(filename, "r") as zipf:
        zipf.extractall()


'''
Delete a file.
'''
def del_file(filename):
    if os.path.isfile(filename):
        os.remove(filename)


'''
Current date in string format.
'''
def time_string():
    now = datetime.now()
    year = str(now.year)
    month = str(now.month)
    day = str(now.day)

    return year, month, day
 

'''
Run PowerShell command to get a list of all installed software including:
    * Name
    * Version
    * Vendor
    * Date Installed
'''
def list_packages():
    p = subprocess.Popen(["powershell.exe", "-ep", "Bypass", "-File",
    "scan_installed.ps1"],
    stdout = sys.stdout)

    # Print output
    p.communicate()


'''
Download CVE data from NVD for year in (zipped) JSON format
    * URL: https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-<YEAR>.json.zip
    * Unzipped filename: nvdce-1.0-<YEAR>.json
'''
def get_cves():
    # Oldest available year in JSON format
    year = 2002

    # Current year
    now = datetime.now()
    current_year = int(now.year)
    latest_file = "nvdcve-1.0-" + str(current_year) + ".json"


    '''
    If latest CVE data has already been downloading, notify user.
    If not, download CVE data up to the latest release.
    '''
    if check_existence(latest_file):
        print("[*] Your CVEs are up to date.\n")

    else:
        print("[*] Updating CVE data...\n")

        while year <= current_year:
            filename = "nvdcve-1.0-" + str(year) + ".json.zip"

            url = "https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename

            unzipped = filename[:-4]

            # Update year to download next file
            year += 1

            # Check if file exists before downloading
            if check_existence(unzipped):
                continue

            # Download file
            download_file(url, filename)

            # Extract ZIP contents
            unzip(filename)

            # Delete ZIP file
            del_file(filename)


'''
Convert from XLSX to CSV.
'''
def xlsx_to_csv(fn, sn, csv_file):
    data_xlsx = pd.read_excel(fn, sn)
    data_xlsx.to_csv(csv_file, encoding='utf-8', index=False)


'''
Read Microsoft Security Bulletin (MSB); XLSX file.
Compare potential vulnerabilities' CVEs against those in the MSB file.
'''
def compare_bulletin(vulnerabilities_file):
    url = "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx"
    fn = "BulletinSearch.xlsx"
    sheet_name = "Bulletin Search"
    csv_file = fn[:-4] + "csv"

    if check_existence(fn):
        print("\n[*] You have already downloaded the Security Updates Bulletin.\n")

    else:
        # Download file
        download_file(url, fn)

    if check_existence(csv_file):
        print("[*] You already have the Security Bulletin CSV file.\n")

    else:
        # Convert from XLSX to CSV
        xlsx_to_csv(fn, sheet_name, csv_file)

    # Potential vulnerabilities file
    try:
        with open(vulnerabilities_file, "r", encoding="latin-1") as f:
            content = f.readlines()

    except Exception as e:
        print(e)


    try:
        # Load the Microsoft Security Bulletin (MSB) workbook and worksheet
        with open(csv_file, "r", encoding="latin-1") as csvf:
            msb = csvf.readlines()

        # Local scan vs. compare files
        location = input("[?] Do you want to run a local scan (L) or use an existing file (F)? \n[*] Enter L or F: ")

        if location == "F" or location == "f":
            version = input("Enter the Windows version (E.g., Windows 7): ")
            last_day = int(input("Enter the date of the last installed KB (E.g., 20170220): "))

            # Load the KB file
            with open("kb_list.txt", "r", encoding="latin-1") as kbl:
                kb_file = kbl.readlines()

        kb_list = []
        for i in msb:
            split_content = i.split(",")
            try:
                cve = split_content[13]
                kb = split_content[2]
                kb = "KB" + kb

                windows = split_content[6]
                d = split_content[0]
                date = d.replace("-", "")
                date = int(date)

                # Local scan
                if location == "L" or location == "l":
                    for line in content:
                        # Check length to avoid blank entries
                        if cve in line and len(cve) > 3:
                            kb_list.append(kb)

                # Compare kb file to MSB by date and Windows version
                if location == "F" or location == "f":
                    if date > last_day:
                        if version in windows:
                            if kb not in kb_file:
                                kb_list.append(kb)

            except Exception as e:
                pass


        # Unique list of KBs
        unique_list = np.unique(kb_list)
        if len(unique_list) == 0:
            print("[*] No matches found.\n")
            print()

        if len(unique_list) > 1:
            print("[!] Missing KB:")

            # Compare the KBs against those already installed.
            if location == "L" or location == "l":
                try:
                    for kb in unique_list:
                        # Run PowerShell Get-HotFix to find missing security updates
                        p = subprocess.Popen(["powershell.exe", "-ep", "Bypass", "Get-HotFix", "-Id", kb],
                                                stdout = sys.stdout)

                        # Print missing KBs
                        print(kb)
                        p.communicate()
                    print()

                except Exception as e:
                    print(e)

            print()

            # Save list of missing KBs to timestamped file.
            current_year, current_month, current_day = time_string()

            unique_array = current_year + current_month + current_day + "_unique_kb.txt"
            with open(unique_array, "a+", encoding="latin-1") as f:
                for item in unique_list:
                    f.write("{}\n".format(item))

    except Exception as e:
        print(e)


'''
Compare CSV file of installed packages against JSON CVE data.
Outputs a file with content that shows:
    * Vendor Name
    * Vulnerable Software
    * Software Version
    * CVE Name
    * CVSS V3 Base Severity
    * CVE Description
'''
def vulnerability_scan(installations_file, nvd_file):
    global latest_scan

    # Installed packages file
    with open(installations_file, "r", encoding="latin-1") as fd:
        installed_data = fd.readlines()

    # NVD CVE file
    with open(nvd_file, "r", encoding="latin-1") as f:
        cve_data = json.load(f)

    # Identify vulnerable software via comparison of installed packages against NVD
    vulnerable_list = []

    for j in cve_data["CVE_Items"]:
        for i in installed_data:
            split_content = i.split(",")
            try:
                # Installed Packages Data
                installed_name = split_content[0]
                installed_name = installed_name.replace(' ', '_').lower()
                installed_version = split_content[1]

                # Vulnerable Software Data
                vendor = j["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
                product = j["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["product_name"]
                version = j["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"][0]["version_value"]
                cve_id = j["cve"]["CVE_data_meta"]["ID"]
                # CVE CVSS V3 Base Severity
                cve_severity = j["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                # CVE Description
                cve_description = j["cve"]["description"]["description_data"][0]["value"]

                '''
                Performing matching.
                If installed packages are present in NVD CVE data file, identify it.
                '''
                try:
                    if product in installed_name and version in installed_version:
                        vulnerable_package = vendor + " " + product + " " + version + " | " + \
                        cve_id + " | Severity: " + cve_severity + " | Description: " + cve_description

                        vulnerable_list.append(vulnerable_package)

                except Exception as e:
                    print(e)

            except:
                pass

    # Unique list of vulnerable packages; Raw has duplicates
    unique_array = np.unique(vulnerable_list)
    print("[!] Vulnerabilities found:")

    # Print statement depending on whether vulnerabilities were found or not
    if len(unique_array) == 0:
        print("[*] No vulnerabilities found.")
    else:
        print(unique_array)
    print("")

    '''
    Save the discovered vulnerabilities to a timestamped text file.
    '''
    current_year, current_month, current_day = time_string()

    latest_scan = current_year + current_month + current_day + "_scan.txt"

    try:
        with open(latest_scan, 'a+') as f:
            for item in unique_array:
                f.write("{}\n\n".format(item))

    except Exception as e:
        print(e)


def main():

    # List installed packages
    location = input("[?] Do you want to run a local scan (L) for installed packages or use an existing file (F)? \n[*] Enter L or F: ")
    if location == "L" or location == "l":
        list_packages()

    # Get NIST Vulnerability Database CVE data
    get_cves()

    # Oldest available year in JSON format
    year = 2002

    # Current data
    now = datetime.now()
    current_month = int(now.month)
    current_year = int(now.year)
    latest_nvd = "nvdcve-1.0-" + str(current_year) + ".json"

    # Run vulnerability scan
    while year <= current_year:
        try:
            host_file = str(current_year) + "_installed.txt"
            nvd_file = "nvdcve-1.0-" + str(year) + ".json"

            print(str(year))
            vulnerability_scan(host_file, nvd_file)

            # Update year to scan next file
            year += 1
        except Exception as e:
            print(e)


    #Run scan to see if any hotfixes or patches have been applied.
    scan_patches = input("[*] Do you want to run a patch scan? (Yes/No)\n: ")

    if scan_patches == "Yes" or scan_patches == "yes" or scan_patches == "Y" or scan_patches == "y":
        compare_bulletin(latest_scan)


main()
