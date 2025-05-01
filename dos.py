import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# Load dataset
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

try:
    train_data = pd.read_csv('KDDTrain+.TXT', header=None, names=columns)
except FileNotFoundError:
    print("Error: Could not find KDDTrain+.TXT")
    exit()

# Define DoS attacks
dos_attacks = [
    'back', 'land', 'neptune', 'pod', 'smurf', 'teardrop',
    'apache2', 'udpstorm', 'processtable', 'mailbomb'
]
train_data['is_dos'] = train_data['attack_type'].apply(lambda x: 1 if x in dos_attacks else 0)

# Separate traffic
normal_traffic = train_data[train_data['attack_type'] == 'normal']
dos_traffic = train_data[train_data['is_dos'] == 1]

# Optimized feature selection
dos_features = [
    'count', 'srv_count', 'serror_rate', 'dst_host_serror_rate',
    'same_srv_rate', 'src_bytes', 'dst_bytes', 'diff_srv_rate', 
    'dst_host_count', 'protocol_type'
]

# Calculate robust thresholds (using IQR for flood features and mean+2std for error rates)
def calculate_threshold(feature, method='iqr'):
    if method == 'iqr':
        q75, q25 = np.percentile(normal_traffic[feature], [75, 25])
        iqr = q75 - q25
        return q75 + 3*iqr
    else:  # mean + 2std
        mean = normal_traffic[feature].mean()
        std = normal_traffic[feature].std()
        return mean + 2*std

thresholds = {
    'count': calculate_threshold('count', 'iqr'),
    'srv_count': calculate_threshold('srv_count', 'iqr'),
    'serror_rate': calculate_threshold('serror_rate', 'std'),
    'dst_host_serror_rate': calculate_threshold('dst_host_serror_rate', 'std'),
    'same_srv_rate': normal_traffic['same_srv_rate'].mean() - 2*normal_traffic['same_srv_rate'].std(),
    'src_bytes_upper': 10000,
    'src_bytes_lower': 200,
    'dst_bytes': calculate_threshold('dst_bytes', 'iqr'),
    'diff_srv_rate': calculate_threshold('diff_srv_rate', 'std'),
    'dst_host_count': calculate_threshold('dst_host_count', 'iqr')
}

print("Optimized DoS Detection Thresholds:")
for k, v in thresholds.items():
    print(f"{k}: {v:.2f}")

# Enhanced detection logic combining both approaches
def detect_dos(row):
    # Pattern 1: High connection rate with small packets
    if (row['count'] > thresholds['count'] and 
        row['src_bytes'] < thresholds['src_bytes_lower']):
        return 1
        
    # Pattern 2: Error rate spike (both error rates must be high)
    if (row['serror_rate'] > thresholds['serror_rate'] and
        row['dst_host_serror_rate'] > thresholds['dst_host_serror_rate']):
        return 1
        
    # Pattern 3: Service flood with abnormal distribution
    if (row['srv_count'] > thresholds['srv_count'] and
        row['same_srv_rate'] < thresholds['same_srv_rate']):
        return 1
        
    # Pattern 4: Protocol-specific anomalies
    if (row['protocol_type'] in ['udp','icmp'] and 
        row['count'] > thresholds['count']/2):
        return 1
        
    # Pattern 5: High destination bytes (data exfiltration)
    if row['dst_bytes'] > thresholds['dst_bytes']:
        return 1
        
    # Pattern 6: Abnormal diff_srv_rate
    if row['diff_srv_rate'] > thresholds['diff_srv_rate']:
        return 1
        
    return 0

# Apply detection
train_data['predicted_dos'] = train_data.apply(detect_dos, axis=1)

# Evaluation
print("\nDoS Detection Performance:")
print("Accuracy:", accuracy_score(train_data['is_dos'], train_data['predicted_dos']))
print("Confusion Matrix:")
print(confusion_matrix(train_data['is_dos'], train_data['predicted_dos']))
print("\nClassification Report:")
print(classification_report(train_data['is_dos'], train_data['predicted_dos']))

# Feature comparison
print("\nFeature Comparison (Normal vs DoS):")
comparison_df = pd.DataFrame({
    'Normal_mean': normal_traffic[dos_features[:-1]].mean(),  # exclude protocol_type
    'DoS_mean': dos_traffic[dos_features[:-1]].mean()
})
comparison_df['DoS/Normal_ratio'] = comparison_df['DoS_mean'] / comparison_df['Normal_mean']
print(comparison_df.round(2))

# Protocol distribution
print("\nProtocol Type Distribution:")
print("Normal traffic:")
print(normal_traffic['protocol_type'].value_counts(normalize=True))
print("\nDoS traffic:")
print(dos_traffic['protocol_type'].value_counts(normalize=True))