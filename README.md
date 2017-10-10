# CVE_Compare

Version 1.1

Jean Gonzalez

Dependencies:
  * requests
  * numpy
  * pathlib
  * xlrd
  * pandas

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

