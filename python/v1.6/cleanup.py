import datetime
import csv

c = datetime.datetime.now()
cy = str(c.year)

destination_file = cy + "_installed_linux.csv"

# Destination file
with open(destination_file, 'a+') as df:
    writer = csv.writer(df)
    # Write headers
    writer.writerow(["Product Name", "Software", "Software Version", "Software Publisher", "Install Date"])

df.close()

# Installations file
with open("installed.txt", 'r') as f:
    installed = f.readlines()

# Device name file
with open("vendor_version_linux.txt", 'r') as fd:
    product = fd.readline()

with open(destination_file, 'a+') as sf:
    writer = csv.writer(sf)

    try:
        for line in installed:
            a = line.split(',')

            # Software name
            b = a[0].split('/')
            name = b[0]

            # Software version
            if len(a) == 5:
                c = a[2]
                version = c[1:]
            if len(a) == 6 or len(a) == 7:
                if a[3] == " amd64":
                    c = a[2]
                    version = c[1:]
                else:
                    c = a[3]
                    version = c[1:]

            # Placeholders
            publisher ="-"
            install_date = "-"

            # Machine name
            device = product[:-1]

            writer.writerow([device, name, version, publisher, install_date])

    except Exception as e:
        print(e)
