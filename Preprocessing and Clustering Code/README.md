# INCAT
Intelligence-driven Cybersecurity Awareness Training

Original Data Source:
https://nvd.nist.gov/vuln/data-feeds and download CVE-2018
The version of this file from Sept 19, 2018 is saved in GitHub in threats.zip, named threats.json.

Preprocessing Data Flow:
Step          Process                                        Input                   Outputs
1             nvd_annotation_data_parser.py                  threats.json            threats.csv  // all threat data
                                                                                     // small sample files for annotations
                                                                                     50_sample_1.csv...50_sample_6.csv 
                                                                                     // remaining data not in a small file
                                                                                     remainder_sample_7.csv
                                                                                     
2             nvd_cluster_data_parser.py                     threats.json            cluster_data.csv . // complete data set
                                                                                     // small dataset for testing
                                                                                     cluster_sample_50.csv
                                                                                     
3             nvd_clustering_hyperparameter_validation.py    cluster_data.csv        // Basic analysis of data
                                                                                     Frequency.csv
                                                                                     // Data for the different clusters
                                                                                     Clusters.csv
                                                                                     // comparison of clustering results
                                                                                     Hyperparameter.png
                                                                                     
4             nvd_clustering.py                             cluster_data.csv        // Data from final selection of 
                                                                                    // hyperparameters
                                                                                    Final_Clustering.csv

