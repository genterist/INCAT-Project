#
# DESCRIPTION:
# This Program  (nvd_annotaion_data_parser.py) parses json files from the national threat database and converts to csv
# files containing randomly selected sets of 50 records containing the ID and Description for annotation processing
#
# NOTE:  not all fields available in the threat database are converted
#
# Captured fields: ID, Description
#
# How to run this program (parameters are optional)
#   python nvd_annotaion_data_parser.py input.json  output.csv
#
# The program takes two optional command line arguments, the name of the input json file and the name of the output csv file.
#
# A summary of errors and exceptions will print to the screen.
#
# SAMPLE OUTPUT
# $ python nvd_annotaion_data_parser.py "Data/threats.json" "Project/threats.csv"
# This is the name of the script:  nvd_annotaion_data_parser.py
# Number of arguments:  3
# The arguments are:  ['jsonParser.py', 'Data/threats.json', 'Project/threats.csv']
# {'Records in file': 8748, 'Records read': 8748, 'No data': 0, 'Error': 0}
#
# DIRECTORY STRUCTURE
# The program is expecting a /Data directory where new files will be written to.
#
# Additional OUTPUT FILES:  small random samples (i.e. files are different every time), with no replacement
# In addition to the main output file containing all of the threat data in csv format
# this program also creates 6 small files of 50 records each 50_sample_1/2/3/etc.csv and a 7th file (remainder_sample_7.csv) containing
# all remaining records.  There is no overlap beween these 7 files.
#
# Version History:
#
#   Written by:  Lydia Sbityakov
#   Date:  10/15/2018
#
#   Modified by: .....
#

import json
import pandas as pd
import sys

DEFAULT_INPUT_FILE_NAME = "Data/threats.json"
DEFAULT_OUTPUT_FILE_NAME = "Data/threats.csv"

input_file = ""
output_file = ""

# If there are no command line arguments the default file names will be used.
if (len(sys.argv)==3):
    input_file = sys.argv[1]
    output_file = sys.argv[2]
else:
    input_file = DEFAULT_INPUT_FILE_NAME
    output_file = DEFAULT_OUTPUT_FILE_NAME

with open(input_file) as recent_threats:
    threats_parsed = json.loads(recent_threats.read())


# DataFrame to hold ID and Description records
df = pd.DataFrame()

# list containing features to be added to the df
features = []


# dictionary object containing program statistics, exceptions, and errors
errorReport = dict([
    ('Records in file', len(threats_parsed['CVE_Items'])),
    ('Records read', 0),
    ('No data', 0),
    ('Error', 0)
])


for index in range(0, len(threats_parsed['CVE_Items']), 1):

    # string containing the ID number
    CVD_ID = ""

    # string containing the description
    description = ""

    try:
        CVD_ID =  threats_parsed['CVE_Items'][index]['cve']['CVE_data_meta']['ID']
        description = threats_parsed['CVE_Items'][index]['cve']['description']['description_data'][0]['value']
        errorReport["Records read"] += 1
    except:
        print("Unknown Exception (General Data) Index ", index, " ", threats_parsed['CVE_Items'][index] )
        errorReport["Error"] += 1

    description =  CVD_ID + " | " + description
    f = [CVD_ID, description]
    features.append(f)

    index += 1

print(errorReport)


# combine id and description into one column
df = pd.DataFrame(features)

# create 6 files of 50 randomly selected records each
df.to_csv(output_file)

sample1 = df.sample(n=50,  replace=False, axis=None)
sample1.to_csv("Data/50_sample_1.csv", index=False, header=False)
df=df.drop(sample1.index)

sample1 = df.sample(n=50,  replace=False, axis=None)
sample1.to_csv("Data/50_sample_2.csv", index=False, header=False)
df=df.drop(sample1.index)

sample1 = df.sample(n=50,  replace=False, axis=None)
sample1.to_csv("Data/50_sample_3.csv", index=False, header=False)
df=df.drop(sample1.index)

sample1 = df.sample(n=50,  replace=False, axis=None)
sample1.to_csv("Data/50_sample_4.csv", index=False, header=False)
df=df.drop(sample1.index)

sample1 = df.sample(n=50,  replace=False, axis=None)
sample1.to_csv("Data/50_sample_5.csv", index=False, header=False)
df=df.drop(sample1.index)

sample1 = df.sample(n=50,  replace=False, axis=None)
sample1.to_csv("Data/50_sample_6.csv", index=False, header=False)
df=df.drop(sample1.index)

# remaining records not in an annotation sample
df.to_csv("Data/remainder_sample_7.csv", index=False, header=False)
