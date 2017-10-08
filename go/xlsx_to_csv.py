'''
Convert from XLSX to CSV.
'''
import numpy as np
import pandas as pd


def xlsx_to_csv(fn, sn, csv_file):
    data_xlsx = pd.read_excel(fn, sn)
    data_xlsx.to_csv(csv_file, encoding='utf-8', index=False)


def main():
    fn = "BulletinSearch.xlsx"
    sheet_name = "Bulletin Search"
    csv_file = fn[:-4] + "csv"
    xlsx_to_csv(fn, sheet_name, csv_file)

main()
