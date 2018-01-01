'''
CVE_Compare.py Dependencies
Run: python setup.py
'''

import subprocess, sys


def check_path():
    try:
        # Find where PIP.exe is
        p = subprocess.Popen(["where.exe", "pip.exe"], stdout = subprocess.PIPE)
        path = str(p.stdout.read())
        # Clean up the path found before adding to system path
        path = path[:path.find("\\pip")]
        path = path[2:-1]
        path = path.replace("\\\\", "\\")

        # Check whether PIP is in the PATH, and if not, add it
        sys_path = str(sys.path)
        if sys_path.find(path):
            print("[*] PIP in PATH. \n")

        else:
            sys.path.append(path)
            print("[*] PIP added to PATH. \n")

    except Exception as e:
        print(e)


def setup(package):
    try:
        p = subprocess.Popen(["pip.exe", "install", package], stdout = sys.stdout)

        # Print output
        p.communicate()

    except Exception as e:
        print(e)


check_path()
setup("pathlib")
setup("requests")
setup("numpy")
setup("xlrd")
setup("pandas")
setup("psycopg2")
