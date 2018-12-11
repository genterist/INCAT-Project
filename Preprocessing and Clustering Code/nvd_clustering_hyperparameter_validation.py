#
# DESCRIPTION:
# This Program  (nvd_clustering_hyperparameter_validation.py) takes a csv data file derived from the nvd database as an input file
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
# 1.  Data assessment, including number of missing fields, values for categorical fields and frequency
#        OUTPUT:  frequency.csv, listing every combination of categorical values with associated vulnerability
#                 to console, info about number of missing values, frequency of categorical values
# 2.  Clustering validation, comparison of 3 different seeding algorithms and number of clusters
#        OUTPUT:  hyperparameter.png, graph comparing various hyperparameters
# 3.  Clustering data, using hyperparameters with the least cost found in #2 and frequency
#        OUTPUT:  Clusters.csv, details of each cluster and frequency
#
# The program takes two optional command line arguments, the name of the input json file and the name of the output csv file.
#
# DIRECTORY STRUCTURE
# The program is expecting a /Data directory where new files will be written to.
#
# SAMPLE OUTPUT
# $ python nvd_clustering_hyperparameter_validation.py cluster_data.csv
# Following is a survey of the data used for clustering.
# Total number of records:   50
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
import matplotlib.pyplot as plt
import sys


#DEFAULT_INPUT_FILE_NAME = "Project/cluster_sample_50.csv"
DEFAULT_INPUT_FILE_NAME = "Project/cluster_data.csv"

# DEFAULT HYPERPARAMETERS
ITERATIONS_MAX = 300   # KModes default
NUMBER_RUNS = 10       # KModes default, number of runs with different centroid seeds
CLUSTERING_ALGORITHMS  = ['Huang', 'Cao', 'random']
NUMBER_OF_CLUSTERS = range(1,236,5)
MAX_COST= 2000000


input_file = ""

# add filename as a command line argument
if (len(sys.argv)==2):
    input_file = sys.argv[1]
else:
    input_file = DEFAULT_INPUT_FILE_NAME


# Global variable
data = pd.read_csv(input_file)

def data_assessment():

    # create a DataFrame to hold the categorical data
    df = pd.DataFrame(data)

    # assess data quality, number of missing values by feature
    # and total number of records
    print("Following is a survey of the data used for clustering.")
    print("Total number of records:  " , len(df))
    print("\nNumber of null values by field:  ")
    print(df.isnull().sum())

    print("\nUnique values for each categorical feature:")
    print(df.groupby(['Attack_Vector'])['Attack_Vector'].count())
    print("\n", df.groupby(['Attack_Complexity'])['Attack_Complexity'].count())
    print("\n", df.groupby(['User_Interaction'])['User_Interaction'].count())
    print("\n", df.groupby(['Privileges_Required'])['Privileges_Required'].count())
    print("\n", df.groupby(['Confidentiality_Impact'])['Confidentiality_Impact'].count())
    print("\n", df.groupby(['Integrity_Impact'])['Integrity_Impact'].count())
    print("\n", df.groupby(['Availability_Impact'])['Availability_Impact'].count())

    # replace missing product and vendor with unknown
    df.fillna("UNKNOWN", inplace=True)

    print("\nThe 10 most common Vendors and frequency of appearance")
    print("If value for Vendor was null or missing it will display as \"UNKNOWN\".")
    vendors = pd.DataFrame(df.groupby('Vendor')['Vendor'].count())
    vendors.rename(columns={'Vendor':'Vendor_Count'}, inplace=True)
    print(vendors.sort_values('Vendor_Count', ascending=False).head(10))

    print("\nThe 10 most common Products and frequency of appearance")
    print("If value for Product was null or missing it will display as \"UNKNOWN\".")
    products = pd.DataFrame(df.groupby('Product')['Product'].count())
    products.rename(columns={'Product':'Product_Count'}, inplace=True)
    print(products.sort_values('Product_Count', ascending=False).head(10))

    # Print Group by query to file containing all combinations of features and frequency
    newdf = df.groupby(['Attack_Vector','Attack_Complexity','User_Interaction','Privileges_Required',
                        'Confidentiality_Impact','Integrity_Impact','Availability_Impact'])['Attack_Vector'].count()
    newdf = pd.DataFrame(newdf)
    newdf.rename(columns={'Attack_Vector':'Count'}, inplace=True)
    newdf.sort_values('Count', ascending=False).to_csv("Data/Frequency.csv")
    print("\nFrequency information for all combinations of categorical values with an associated record have been printed to frequency.csv")


def clustering_validation():

    # create a DataFrame to hold the categorical data
    df = pd.DataFrame(data)

    # remove all features not appropriate for clustering
    df = df.drop(['CVD_ID', 'Date_Published', 'Date_Modified', 'Vendor', 'Product'], axis=1)

    # Clustering hyperparameters
    # n_clusters:  Number of clusters possbile values for this study are between 1:236, however we are looking for the
    # optimum in the range of 5-20
    # max_iter:  Maximum number of iterations, use default of 300
    # init:  Initialization function 'Huang', 'Cao', 'random'
    # n_init:  number of runs with different centroid seeds (does not apply to Cao), use default of 10
    # create array to store data for evaluating the clustering results
    # cost is the sum of distance of all points to their assigned centroid
    # [n_clusters, max_iter, init, n_init, cost]

    # ITERATIONS_MAX = 300   # KModes default
    # NUMBER_RUNS = 10       # KModes default, number of runs with different centroid seeds
    # CLUSTERING_ALGORITHMS  = ['Huang', 'Cao', 'random']
    # NUMBER_OF_CLUSTERS = range(5,25,5)

    results = []
    max_iter = ITERATIONS_MAX
    n_init = NUMBER_RUNS
    init = CLUSTERING_ALGORITHMS
    n_clusters = NUMBER_OF_CLUSTERS
    cost = 1000000
    centroids = []
    labels = []
    best = []

    # evaluate the various clusters for cost
    for type in init:

        for num in n_clusters:
            km = KModes(n_clusters=num, init=type, verbose=0)
            km.fit_predict(df)
            ls = [num, max_iter, type, n_init, km.cost_]
            results.append(ls)
            if (km.cost_ < cost):
                centroids = km.cluster_centroids_
                labels = km.labels_
                best = ls
                cost = km.cost_


    df_results = pd.DataFrame(results, columns=['Num_Clusters','Max_Iter','Init_Algorithm', 'Num_Iter' ,'Cost' ])
    print("\nClustering Comparison Results\n", df_results)

    Huang = pd.DataFrame(df_results.loc[df_results['Init_Algorithm'] == 'Huang'])
    x = Huang['Num_Clusters']
    y1 = Huang['Cost']

    random = pd.DataFrame(df_results.loc[df_results['Init_Algorithm'] == 'random'])
    y2 = random['Cost']

    Cao = pd.DataFrame(df_results.loc[df_results['Init_Algorithm'] == 'Cao'])
    y3 = Cao['Cost']

    # plot the hyperparameter comparison data
    plt.plot(x, y3, label='Cao')
    plt.plot(x, y1, label='Huang')
    plt.plot(x, y2, label='random')
    plt.ylabel('Cost')
    plt.xlabel('Number of Clusters')
    plt.title("Hyperparameter Comparision for Categorical Clusters")
    plt.legend()
    plt.savefig("Data/Hyperparameter.png")
    # plt.show()

    # Display the data about the best performing cluster
    display(df, best, centroids, labels)



def display(df, best, centroids, labels):

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
    print("\nTotal Cost of Selected Clustering Hyperparameters: ", best[4])
    print("Optimal Number of Clusters:  ", best[0])
    print("Optimal Algorithm: ", best[2])
    print("Cluster data is printed to Clusters.csv.")
    print(l.sort_values('Count', ascending=False))
    l.sort_values('Count', ascending=False).to_csv("Data/Clusters.csv", index=False)


def main():
    # assess data quality, general statistics
    data_assessment()

    # perform clustering clustering results
    # display final clustering results
    clustering_validation()

main()



