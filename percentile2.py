import pandas as pd
import numpy as np

# Load the dataset
train_data = pd.read_csv('KDDTrain+.TXT', header=None)
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "level"
]
train_data.columns = columns

# Define attack categories
attack_categories = {
    'DoS': ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop'],
    'Probe': ['ipsweep', 'nmap', 'portsweep', 'satan'],
    'U2R': ['buffer_overflow', 'loadmodule', 'perl', 'rootkit'],
    'R2L': ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy', 'warezclient', 'warezmaster']
}

# Features to analyze
features = [
    'src_bytes', 'dst_bytes', 'count', 'srv_count', 'duration',
    'diff_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_count',
    'serror_rate', 'dst_host_serror_rate', 'wrong_fragment',
    'hot', 'num_failed_logins', 'num_compromised',
    'num_file_creations', 'num_access_files'
]

# Create analysis dataframe
analysis_df = pd.DataFrame(index=features)

# Calculate percentiles for each attack type
percentiles = [75]

# Create a multi-index for the table
index = pd.MultiIndex.from_product([attack_categories.keys(), percentiles], names=['Attack Type', 'Percentile'])

# Initialize the results dataframe
results = pd.DataFrame(index=index, columns=features)

# Calculate percentiles for each attack type and feature
for attack_type, attacks in attack_categories.items():
    attack_data = train_data[train_data['attack_type'].isin(attacks)]
    
    for feature in features:
        for p in percentiles:
            try:
                results.loc[(attack_type, p), feature] = np.percentile(attack_data[feature], p)
            except:
                results.loc[(attack_type, p), feature] = np.nan

# Display the table
# pd.set_option('display.max_columns', None)
# pd.set_option('display.width', 1000)
# print("Feature Percentiles by Attack Type:")
# print(results)

# Save to CSV
# results.to_csv('attack_feature_percentiles.csv')
# print("\nTable saved to 'attack_feature_percentiles.csv'")

# Create a transposed version for better readability
transposed = results.stack().unstack(level=[0,1])
print("\nTransposed View (Features as Rows):")
print(transposed)
transposed.to_csv('transposed_attack_feature_percentiles.csv')

