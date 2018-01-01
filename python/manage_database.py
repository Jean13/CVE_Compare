'''
Manage CVE_Compare vulnerabilities database.

'''

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import getpass


def get_details():
    print("Database Details")
    db_name = input("Enter the database name: ")
    user = input("Enter the username: ")
    host = input("Enter the host (E.g., localhost): ")
    password = getpass.getpass()

    # Connection
    conn = psycopg2.connect(dbname=db_name, user=user, host=host, password=password)
    # Commit database
    conn.autocommit = True

    # Open a cursor to perform database operations
    cur = conn.cursor()

    return db_name, user, host, password, conn, cur


def create_database():
    # Welcome
    print("Create a Database")
    print("Log in")
    db_name, user, host, password, conn, cur = get_details()

    db_name = input("Enter the name of the database to create: ")

    # Create the database
    cur.execute('CREATE DATABASE {};'.format(db_name))

    # Close the cursor and the connection
    cur.close()
    conn.close()


'''
This was pre-packaged with the vulnerabilities database use in mind

Formatting:
<column name> <data type>

Relevant Data Types:
* serial PRIMARY KEY
* integer
* text
'''
def create_table():
    print("Create a Table")
    print("Log in")
    db_name, user, host, password, conn, cur = get_details()

    # Create the table
    cur.execute("CREATE TABLE Vulnerabilities(No integer PRIMARY KEY, Vendor text, Product text, Version text, CVE_ID text, Severity text, Description text)")


# Copy data from a CSV file to a database table
def csv_to_table():
    print("Copy Data from CSV to Database")
    print("Log in")
    db_name, user, host, password, conn, cur = get_details()

    csv_file = input("Enter the path to the CSV file: ")
    table_name = input("Enter the name of the table to insert to: ")

    with open(csv_file, 'r') as f:
           next(f)
           next(f)
           cur.copy_from(f, table_name, sep=',')


# Manually add data to an existing table
def add_data():
    print("Insert data to the Database")
    print("Log in")
    db_name, user, host, password, conn, cur = get_details()

    no = int(input("Enter the index number: "))
    vendor = input("Enter the vendor name: ")
    product = input("Enter the product name: ")
    version = input("Enter the product version")
    cve_id = input("Enter the CVE ID: ")
    severity = input("Enter the severity: ")
    description = input("Enter a description: ")

    cur.execute("INSERT INTO vulnerabilities (no, vendor, product, version, cve_id, severity, description) VALUES (%d %s %s %s %s %s %s)",
    no, vendor, product, version, cve_id, severity, description)


# Manually delete data from an existing table
def remove_data():
    print("Insert data to the Database")
    print("Log in")
    db_name, user, host, password, conn, cur = get_details()

    no = int(input("Enter the index number (no) of the entry to delete: "))

    cur.execute("DELETE FROM vulnerabilities WHERE no = %d", (no))


def connect_database():
    print("Connect to Database")
    # Connect to database
    db_name, user, host, password, conn, cur = get_details()


# The main function is for debugging purposes
def main():

    db_exists = input("Does the database you want to connect to exist?\n: ")
    if db_exists == "No" or db_exists == "no" or db_exists == "N" or db_exists == "n":
        create_database()

    else:
        # Connect to existing database
        #connect_database()

        # Create a table
        #create_table()

        # Add CSV data to table
        #csv_to_table()




main()
