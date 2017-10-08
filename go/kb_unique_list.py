'''
Make a list of unique items from Microsoft Security Bulletin CSV.
'''
from datetime import datetime
import numpy as np

def csv_unique_list():

    now = datetime.now()
    current_year = str(now.year)
    current_month = str(now.month)
    current_day = str(now.day)
    current_date = current_year + current_month + current_day

    latest_scan = current_date+ "_vulnerability_scan.txt"

    # Potential vulnerabilities file
    try:
        with open(latest_scan, "r", encoding="latin-1") as f:
            content = f.readlines()

    except Exception as e:
        print(e)

    try:
      # Load the Microsoft Security Bulletin (MSB) workbook and worksheet
      csv_file = "BulletinSearch.csv"
      with open(csv_file, "r", encoding="latin-1") as csvf:
          msb = csvf.readlines()

      kb_list = []
      for i in msb:
          split_content = i.split(",")
          try:
              cve = split_content[13]
              kb = split_content[2]
              kb = "KB" + kb

              for line in content:
                  # Check length to avoid blank entries
                  if cve in line and len(cve) > 3:
                      kb_list.append(kb)

          except Exception as e:
              pass

      # Unique list of KBs
      unique_list = np.unique(kb_list)
      for i in unique_list:
          print(i)

      # Save list of KBs to a file  
      unique_array = "unique_kb.txt"
      with open(unique_array, "a+", encoding="latin-1") as f:
          for item in unique_list:
              f.write("{}\n".format(item))

    except Exception as e:
        pass

csv_unique_list()
