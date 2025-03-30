import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import numpy as np

# Load the training dataset
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

# Assign column names
train_data.columns = columns

# Verify changes
print("First 10 rows of the dataset:")
print(train_data.head(10))

# Check for missing values
print("\nMissing values summary:")
missing_values = train_data.isnull().sum()
print(missing_values)

# If there are any missing values, handle them
if missing_values.any():
    print("\nHandling missing values...")
    # For numerical columns, fill with median
    num_cols = train_data.select_dtypes(include=[np.number]).columns
    train_data[num_cols] = train_data[num_cols].fillna(train_data[num_cols].median())
    
    # For categorical columns, fill with mode
    cat_cols = train_data.select_dtypes(include=['object']).columns
    for col in cat_cols:
        train_data[col] = train_data[col].fillna(train_data[col].mode()[0])
    
    print("Missing values after handling:")
    print(train_data.isnull().sum())

# Check for duplicate rows
print("\nNumber of duplicate rows:", train_data.duplicated().sum())

# Check attack types distribution
print("\nAttack type distribution:")
print(train_data['attack_type'].value_counts())

# Create binary label (0 for normal, 1 for attack)
train_data['label'] = train_data['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)

# For more detailed multi-class classification, you might want to keep attack categories
# Map attack types to categories (DoS, Probe, R2L, U2R, Normal)
attack_mapping = {
    'normal': 'normal',
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS',
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R'
}

train_data['attack_category'] = train_data['attack_type'].map(attack_mapping)

# Drop the original attack_type column
train_data.drop(columns=['attack_type'], inplace=True)

# Verify changes
print("\nLabel distribution (0=normal, 1=attack):")
print(train_data['label'].value_counts())

print("\nAttack category distribution:")
print(train_data['attack_category'].value_counts())

# Save the cleaned dataset
train_data.to_csv('cleaned_train_data.csv', index=False)
print("\nCleaned dataset saved to 'cleaned_train_data.csv'")