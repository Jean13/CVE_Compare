'''
CVE Compare
Version 1.6

Functionality:
Scans software in Windows and Linux and compares against the
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

Installations Scan Identifies:
    * Machine Name
    * Software
    * Software Version
    * Software Publisher
    * Installation Date
'''

import subprocess, sys, os
from datetime import datetime
import requests
import zipfile
import json
import numpy as np
import pandas as pd
import csv


'''
Check whether a file already exists.
'''
def check_existence(filename):
    the_file = os.path.isfile(filename)
    if the_file:
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
    * URL: https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-<YEAR>.json.zip
    * Unzipped filename: nvdce-1.1-<YEAR>.json
'''
def get_cves():
    # Oldest available year in JSON format
    year = 2002

    # Current year
    now = datetime.now()
    current_year = now.year
    latest_file = "nvdcve-1.1-" + str(current_year) + ".json"


    '''
    If latest CVE data has already been downloading, notify user.
    If not, download CVE data up to the latest release.
    '''
    if check_existence(latest_file):
        print("[*] Your CVEs are up to date.\n")

    else:
        print("[*] Updating CVE data...\n")

        while year <= current_year:
            filename = "nvdcve-1.1-" + str(year) + ".json.zip"

            url = "https://nvd.nist.gov/feeds/json/cve/1.1/" + filename

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
Add column and data to CSV file.
'''
def csv_add_column(filename, column_name, data):
    try:
        df = pd.read_csv(filename, keep_default_na=False)

        data = pd.Series(data)
        df[column_name] = data

        # Save changes
        df.to_csv(filename, index=False)

    except Exception as e:
        print(e)


'''
Read Microsoft Security Bulletin (MSB); XLSX file.
Compare potential vulnerabilities' CVEs against those in the MSB file.
'''
def compare_bulletin(vulnerabilities_file):
    url = "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx"
    fn = "BulletinSearch.xlsx"
    sheet_name = "Bulletin Search"
    csv_file = fn[:-4] + "csv"

    if check_existence(csv_file):
        print("[*] You already have the Security Bulletin CSV file.\n")

    else:
        # Download file
        download_file(url, fn)
        # Convert from XLSX to CSV
        xlsx_to_csv(fn, sheet_name, csv_file)
        # Delete the XLSX
        del_file(fn)

    # Potential vulnerabilities file
    try:
        with open(vulnerabilities_file, "r", encoding="latin-1") as f:
            content = f.readlines()

    except Exception as e:
        print(e)


    try:
        # Load the Microsoft Security Bulletin (MSB) workbook and worksheet
        with open(csv_file, "r", encoding="latin-1") as csvf:
            # Skip header
            next(csvf)
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
        if unique_list.size == 0:
            print("[*] No matches found.\n")
            print()

        if unique_list.size > 0:
            print("[!] Missing KB:")

            # Compare the KBs against those already installed.
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

            unique_array = current_year + current_month + current_day + "_unique_kb.csv"
            with open(unique_array, "a+", encoding="latin-1") as f:
                writer = csv.writer(f)
                writer.writerow(["Missing KBs"])
                for item in unique_list:
                    writer.writerow([item])
                f.close()


            # Save list of missing KBs to the Vulnerabilities file.
            csv_add_column(latest_scan, "KBs", unique_list)

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
def vulnerability_scan(installations_file, nvd_file, device_data, os, operating_system):
    global temp, latest_scan

    # Installed packages file
    with open(installations_file, "r", encoding="latin-1") as fd:
        installed_data = fd.readlines()

    # NVD CVE file
    with open(nvd_file, "r", encoding="latin-1") as f:
        cve_data = json.load(f)

    # Time-stamped file with discovered vulnerabilities.
    current_year, current_month, current_day = time_string()
    latest_scan = current_year + current_month + current_day + "_scan.csv"
    date_scanned = current_year + '-' + current_month + '-' + current_day

    # Temporary file will have duplicates
    temp = "temp_scan.csv"
    with open(temp, 'a+') as sf:
        writer = csv.writer(sf)
        # Write headers
        writer.writerow(["Vendor", "Product", "Version", "CVE ID", "Severity", "Score", "Vector String", "Description", "CVE Released", "Date Scanned", "Device Data", "Operating System"])

    sf.close()

    # Identify vulnerable software via comparison of installed packages against NVD
    with open(temp, 'a+') as sf:
        writer = csv.writer(sf)

        for j in cve_data["CVE_Items"]:
            for i in installed_data:
                split_content = i.split(",")
                try:
                    # Installed Packages Data
                    if operating_system == "W":
                        installed_name = split_content[0]
                        installed_name = installed_name.replace(' ', '_').lower()
                        installed_version = split_content[1].strip('"')
                    if operating_system == "L":
                        installed_name = split_content[1]
                        installed_name = installed_name.replace(' ', '_').lower()
                        installed_version = split_content[2]

                    # Vulnerable Software Data
                    vendor = j["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
                    product = j["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["product_name"]
                    v_list = j["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["version"]["version_data"]
                    v_arr = [n["version_value"] for n in v_list]

                    for v in v_arr:
                        if v in installed_version:
                            version = v

                            #if "10.0.45.2" in version:
                            #    print(product + " " + version)
                            #    print(installed_version)


                    cve_id = j["cve"]["CVE_data_meta"]["ID"]

                    try:
                        # If older metric version, v2
                        if "baseMetricV2" in j["impact"]:
                            # CVE CVSS V2 Base Severity
                            cve_severity = j["impact"]["baseMetricV2"]["severity"]
                            # CVE CVSS V2 Base Score
                            cve_score = j["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                            # CVSS Vector String
                            vector_string = j["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]

                        # Otherwise, it's the newer v3
                        else:
                            # CVE CVSS V3 Base Severity
                            cve_severity = j["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                            # CVE CVSS V3 Base Score
                            cve_score = j["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                            # CVSS Vector String
                            vector_string = j["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]

                    except Exception as e:
                        print(e)

                    # CVE Description
                    cve_description = j["cve"]["description"]["description_data"][0]["value"]
                    # Remove commas from CVE Description. This is done so as to keep the CSV format.
                    cve_description = cve_description.replace(',', '')
                    # Date the CVE was published
                    cve_released = j["publishedDate"]
                    cve_released = cve_released[:10]


                    '''
                    Performing matching.
                    If installed packages are present in NVD CVE data file, identify it.
                    '''
                    try:
                        if product in installed_name and version == installed_version:
                            writer.writerow([vendor, product, version, cve_id, cve_severity, cve_score, vector_string, cve_description, cve_released, date_scanned, device_data, os])

                    except Exception as e:
                        print(e)

                except:
                    pass


def unique_file(duplicates_file, new_file):
    try:
        with open(duplicates_file, 'r') as in_file, open(new_file, 'w') as out_file:
            seen = set()
            for line in in_file:
                if line in seen: continue

                seen.add(line)
                out_file.write(line)

        # Delete the temporary file with duplicates
        del_file(duplicates_file)
    except Exception as e:
        print(e)


def print_file(file_to_print):
    with open(file_to_print) as vf:
        for line in vf:
            print(line)
    print("")


def csv_enum(filename):
    try:
        df = pd.read_csv(filename, keep_default_na=False)
        idx = 0

        # Count rows
        enume = []
        for i, row in df.iterrows():
            enume.append(i)

        # Insert an enumeration row
        df.insert(loc=idx, column="No", value=enume)
        # Save changes
        df.to_csv(filename, index=False)

    except Exception as e:
        print(e)


def installed2csv(installations_file, destination_file, device_data):
    # Name of the device being tested
    product_name = device_data

    # Installed packages file
    with open(installations_file, "r", encoding="latin-1") as fd:
        # Skip headers
        next(fd)
        next(fd)
        installed_data = fd.readlines()

    # Create CSV file
    with open(destination_file, 'a+') as sf:
        writer = csv.writer(sf)
        # Write headers
        writer.writerow(["Product Name", "Software", "Software Version", "Software Publisher", "Install Date"])

    sf.close()

    # Write data to file
    with open(destination_file, 'a+') as sf:
        writer = csv.writer(sf)

        for i in installed_data:
            split_content = i.split(",")
            try:
                if split_content[0] == "":
                    pass
                else:
                    software_name = split_content[0].replace('"', '')
                    software_version = split_content[1].replace('"', '')
                    software_publisher = split_content[2].replace('"', '')
                    install_date = split_content[3]
                    #install_date = install_date.replace('"', '')

                    writer.writerow([product_name, software_name, software_version, software_publisher, install_date])

            except Exception as e:
                print(e)


def remove_blanklines(fn):
    df = pd.read_csv(fn, keep_default_na=False)
    df.dropna()
    df.to_csv(fn, index=False)


def main():

    # Windows vs Linux query
    operating_system = input("[?] Is the target Linux or Windows? \n[*] Enter L or W: ")

    if operating_system == "W":
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
    current_month = now.month
    current_year = now.year
    latest_nvd = "nvdcve-1.1-" + str(current_year) + ".json"

    if operating_system == "W":
        # Device data - Vendor and Version
        device_data = ''
        try:
            with open('vendor_version.txt', 'r') as fp:
                device_data = fp.readline()
                device_data = device_data[3:-2]
                device_data = device_data.replace('  ', ' ')
        except:
            pass

        # Operating System Data
        os = ''
        try:
            with open('windows_ver.txt', 'r') as fn:
                lines = fn.readlines()
                os = lines[6]
                os = ''.join(os)
        except:
            pass

    if operating_system == "L":
        device_data = ''
        os = ''
        with open('vendor_version_linux.txt', 'r') as lp:
            device_data = lp.readline()
            device_data = device_data[:-1]
        with open('linux_ver.txt', 'r') as lv:
            line = lv.readline()
            os = line[:-1]


    # Run vulnerability scan
    host_file = ''
    while year <= current_year:
        try:
            if operating_system == "W":
                host_file = str(current_year) + "_installed_windows.txt"
            if operating_system == "L":
                host_file = str(current_year) + "_installed_linux.csv"

            nvd_file = "nvdcve-1.1-" + str(year) + ".json"

            print("Scanning year: " + str(year))
            vulnerability_scan(host_file, nvd_file, device_data, os, operating_system)

            # Update year to scan next file
            year += 1
        except Exception as e:
            print(e)

    # Create vulnerabilities file without duplicates
    unique_file(temp, latest_scan)

    # Print contents of vulnerabilities file
    print_yo = input("[*] Do you want to print the contents of the vulnerabilities file?\n \
Note that this is a CSV file, better viewed externally.\n: ")

    if print_yo == "Yes" or print_yo == "yes" or print_yo == "Y" or print_yo == "y":
        print("[!] Vulnerabilities found:")
        print_file(latest_scan)

    if operating_system == "L":
        unique_list = []
        # Adding a KBs column to the CSV to maintain compatibility
        csv_add_column(latest_scan, "KBs", unique_list)

    if operating_system == "W":
        #Run scan to see if any hotfixes or patches have been applied.
        scan_patches = input("[*] Do you want to run a patch scan? (Yes/No)\n: ")

        if scan_patches == "Yes" or scan_patches == "yes" or scan_patches == "Y" or scan_patches == "y":
            compare_bulletin(latest_scan)
            unique_kb_file = current_year + current_month + current_day + "_unique_kb.csv"
            remove_blanklines(unique_kb_file)

        # Enumerate rows in vulnerabilities CSV file.
        #csv_enum(latest_scan)

        # Date in string format
        current_year, current_month, current_day = time_string()

        # Copy the installed data txt contents to a CSV file.
        installations_file = current_year + "_installed_windows.txt"
        destination_file = current_year + "_installed_windows.csv"
        installed2csv(installations_file, destination_file, device_data)

        # Remove blank lines from CSV
        remove_blanklines(destination_file)

        # Clean up
        del_file("vendor_version.txt")
        del_file("windows_ver.txt")


main()
