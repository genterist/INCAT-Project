#
# DESCRIPTION:
# This Program  (nvd_cluster_data_parser.py) parses json files from the national threat database and converts to csv
# NOTE:  not all fields available in the threat database are converted including version information
#
#
# Captured fields:
# General Threat Information:
# Date Published, Date Modified, Description, Vendor - when available, Product - when available
#
# Base Metric 3 (BM3)  threat analysis when available:
# "bm3AttackVector", "bm3attackComplexity", "bm3userInteraction", "bm3privilegesRequired",
# "bm3ConfidentialityImpact", "bm3IntegrityImpact", "bm3availabilityImpact"
#
# How to run this program
#   python nvd_cluster_data_parser.py input.json  output.csv
#
# The program takes two command line arguments, the name of the input json file and the name of the output csv file.
# If command line arguments are not provided defaults will be used.
#
# A summary of errors and exceptions will print to the screen.
#
# DIRECTORY STRUCTURE
# The program is expecting a /Data directory where new files will be written to.
#
# SAMPLE OUTPUT
# $ python nvd_cluster_data_parser.py "Data/threats.json" "Project/threats.csv"
# This is the name of the script:  nvd_cluster_data_parser.py
# Number of arguments:  3
# The arguments are:  ['nvd_cluster_data_parser.py', 'Data/threats.json', 'Project/threats.csv']
# {'Records in file': 8748, 'Records read': 8748, 'No vendor/product data': 2555, 'No BM3 only data': 0, 'BM3 read': 6851, 'No data': 0, 'Error': 0}
#
#
# Version History:
#
#   Written by:  Lydia Sbityakov
#   Date:  10/15/2018
#
#   Modified by:  L. Sbityakov 12/03/2018, bug fix and additional comments
#



import json
import pandas as pd
import sys

DEFAULT_INPUT_FILE_NAME = "Data/threats.json"
DEFAULT_OUTPUT_FILE_NAME = "Data/cluster_data.csv"

input_file = ""
output_file = ""

# add filename as a command line argument
if (len(sys.argv)==3):
    input_file = sys.argv[1]
    output_file = sys.argv[2]
else:
    input_file = DEFAULT_INPUT_FILE_NAME
    output_file = DEFAULT_OUTPUT_FILE_NAME

with open(input_file) as recent_threats:
    threats_parsed = json.loads(recent_threats.read())


# DataFrame to hold the vulnerability records
df = pd.DataFrame()

# flag to indicate that the data for the record is complete
complete = False

col_names = ['CVD_ID', 'Date_Published', 'Date_Modified', "Vendor", "Product", "Attack_Vector", "Attack_Complexity",
                 "User_Interaction", "Privileges_Required", "Confidentiality_Impact", "Integrity_Impact", "Availability_Impact"]

# list of contain each record as it is retrived from the database
features = []
ls = []
ls_bm3 = []


errorReport = dict([
    ('Records in file', len(threats_parsed['CVE_Items'])),
    ('Records read', 0),
    ('No vendor/product data', 0),
    ('BM3 read', 0),
    ('No BM3 data', 0),
    ('No data', 0),
    ('Error', 0)
])

for index in range(0, len(threats_parsed['CVE_Items']), 1):

    try:
        CVD_ID =  threats_parsed['CVE_Items'][index]['cve']['CVE_data_meta']['ID']
        published_date = threats_parsed['CVE_Items'][index]['publishedDate']
        modified_date = threats_parsed['CVE_Items'][index]['lastModifiedDate']

        if (threats_parsed['CVE_Items'][index]['cve']['affects']['vendor']['vendor_data']!=[]):
            product_name = threats_parsed['CVE_Items'][index]['cve']['affects']['vendor']['vendor_data'][0]['product']['product_data'][
                    0]['product_name']
            vendor_name = threats_parsed['CVE_Items'][index]['cve']['affects']['vendor']['vendor_data'][0][
                'vendor_name']
        else:
            product_name = ""
            vendor_name = ""
            errorReport["No vendor/product data"] += 1

        ls = [CVD_ID, published_date, modified_date, vendor_name, product_name]

        errorReport["Records read"] += 1

    except:
        print("Unknown Exception (General Data) Index ", index, " ", threats_parsed['CVE_Items'][index] )
        errorReport["Error"] += 1

    try:
        if (threats_parsed['CVE_Items'][index]['impact']!={}):
            bm3AttackVector = threats_parsed['CVE_Items'][index]['impact']['baseMetricV3']['cvssV3']['attackVector']
            bm3attackComplexity = threats_parsed['CVE_Items'][index]['impact']['baseMetricV3']['cvssV3'][
                'attackComplexity']
            bm3userInteraction = threats_parsed['CVE_Items'][index]['impact']['baseMetricV3']['cvssV3'][
                'userInteraction']
            bm3privilegesRequired = threats_parsed['CVE_Items'][index]['impact']['baseMetricV3']['cvssV3'][
                'privilegesRequired']
            bm3confidentialityImpact = threats_parsed['CVE_Items'][index]['impact']['baseMetricV3']['cvssV3'][
                'confidentialityImpact']
            bm3integrityImpact = threats_parsed['CVE_Items'][index]['impact']['baseMetricV3']['cvssV3'][
                'integrityImpact']
            bm3availabilityImpact = threats_parsed['CVE_Items'][index]['impact']['baseMetricV3']['cvssV3'][
                'availabilityImpact']

            ls_bm3 = [bm3AttackVector, bm3attackComplexity, bm3userInteraction,
                    bm3privilegesRequired, bm3confidentialityImpact,
                     bm3integrityImpact, bm3availabilityImpact]

            errorReport["BM3 read"] += 1
            complete = True

        else:
            ls_bm3 = ["", "", "", "", "", "", ""]

    except KeyError:
        # print("Key Error Exception (BM3 Data) Index ", index, " ", threats_parsed['CVE_Items'][index] )
        # no bm2 or 3 data
        errorReport["No BM3 data"] += 1
        ls_bm3 = ["", "", "", "", "", "", ""]

    except:
        print("Unknown Exception (BM3 Data) Index ", index, " ", threats_parsed['CVE_Items'][index] )
        errorReport["Error"] += 1

    if complete==True:
        features.append(ls + ls_bm3)
        complete = False

    index += 1

# output error report and create csv file
print(errorReport)
df = pd.DataFrame(features, columns=col_names)
df.to_csv(output_file, index=False)

# create short sample file for testing
sample1 = df.sample(n=50,  replace=False, axis=None)
sample1.to_csv("Data/cluster_sample_50.csv", index=False)
