# DESCRIPTION:
# This Program  (nvd_clustering.py) takes a csv data file derived from the nvd database as an input file
# The format of the csv file is:
# CVD_ID
# Date_Published
# Date_Modified
# Vendor
# Product
# Attack_Vector
# Attack_Complexity
# User_Interaction
# Privileges_Required
# Confidentiality_Impact
# Integrity_Impact
# Availability_Impact
#
# NOTE:  not all fields are used in processing
#
# This program performs the following tasks:
#
# Clusters data, using hyperparameters selected based on validation
#        OUTPUT:  Final_Clusters.csv, details of each cluster and frequency
#
# The program takes two optional command line arguments, the name of the input json file and the name of the output csv file.
#
# DIRECTORY STRUCTURE
# The program is expecting a /Data directory where new files will be written to.
#
# SAMPLE OUTPUT
# $ python nvd_clustering.py cluster_data.csv
# ....
#
# Version History:
#
#   Written by:  Lydia Sbityakov
#   Date:  12/03/2018
#
#   Modified by: .....
#


import pandas as pd
from kmodes.kmodes import KModes
import sys

#DEFAULT_INPUT_FILE_NAME = "Project/cluster_sample_50.csv"
DEFAULT_INPUT_FILE_NAME = "Project/cluster_data.csv"

# HYPERPARAMETERS
ITERATIONS_MAX = 300   # KModes default
NUMBER_RUNS = 10       # KModes default, number of runs with different centroid seeds
CLUSTERING_ALGORITHM  = 'Huang'
NUMBER_OF_CLUSTERS = 10
MAX_COST= 1000000

input_file = ""

# add filename as a command line argument
if (len(sys.argv)==2):
    input_file = sys.argv[1]
else:
    input_file = DEFAULT_INPUT_FILE_NAME

# Global variable
data = pd.read_csv(input_file)

def cluster():

    # create a DataFrame to hold the categorical data
    df = pd.DataFrame(data)

    # remove all features not appropriate for clustering
    df = df.drop(['CVD_ID', 'Date_Published', 'Date_Modified', 'Vendor', 'Product'], axis=1)

    km = KModes(n_clusters=NUMBER_OF_CLUSTERS, init=CLUSTERING_ALGORITHM, verbose=0)
    km.fit_predict(df)
    centroids = km.cluster_centroids_
    labels = km.labels_
    cost = km.cost_

    # add counts to this dataframe
    l = pd.DataFrame(centroids, columns=df.columns)

    # add assigned cluster to record
    df['Cluster'] = labels
    clusters = pd.DataFrame(df.groupby('Cluster')['Cluster'].count())
    clusters.rename(columns={'Cluster':'Cluster_Count'}, inplace=True)

    cnt = []
    for i in range(0, len(clusters)):
         cnt.append(clusters.iloc[i][0])

    l['Count'] = cnt
    print("\nTotal Cost of Selected Clustering Hyperparameters: ", cost)
    print("Number of Clusters:  ", NUMBER_OF_CLUSTERS)
    print("Algorithm: ", CLUSTERING_ALGORITHM)
    print("Cluster data is printed to Final_Clusters.csv.")
    print(l.sort_values('Count', ascending=False))
    l.sort_values('Count', ascending=False).to_csv("Data/Final_Clusters.csv", index=False)



def main():

    # perform clustering clustering results
    # display final clustering results
    cluster()

main()
