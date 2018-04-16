# CVE_Compare

Version 1.6

Jean Gonzalez


To install:
In a terminal, run: python setup.py

To run:
In a terminal, run: python cve_compare.py


Functionality:
Scans software in operating system (Windows) and compares against the
NIST Vulnerability Database to identify present vulnerabilities.
Includes optional scan for Microsoft hotfixes and patches.

Identifies:
  *  Vendor Name
  *  Vulnerable Software
  *  Software Version
  *  CVE Name
  *  CVSS V3 Base Severity
  *  CVE Description

Hotfix/Patch Scan Identifies:
  *  Missing KBs as per identified vulnerabilities

Files:
  *  cve_compare.py
  *  scan_installed.ps1
  *  setup.py
  *  README.txt

Functionality:
Scans software in Windows and Linux and compares against the
NIST Vulnerability Database (NVD) to identify present vulnerabilities.
Includes optional scan for Microsoft hotfixes and patches.

Identifies:
  *  Vendor Name
  *  Vulnerable Software
  *  Software Version
  *  CVE Name
  *  CVSS V3 Base Severity
  *  CVE Description

Hotfix/Patch Scan Identifies:
  *  Missing KBs as per identified vulnerabilities
  *  Missing KBs as per last applied hotfix date

Installations Scan Identifies:
  *  Machine Name
  *  Software
  *  Software Version
  *  Software Publisher
  *  Installation Date
  
