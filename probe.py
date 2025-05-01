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

# Define Probe attacks
probe_attacks = [
    'satan', 'ipsweep', 'nmap', 'portsweep', 'mscan', 'saint'
]
train_data['is_probe'] = train_data['attack_type'].apply(lambda x: 1 if x in probe_attacks else 0)

# Analyze traffic
normal_traffic = train_data[train_data['attack_type'] == 'normal']
probe_traffic = train_data[train_data['is_probe'] == 1]

# Improved feature selection based on your output analysis
probe_features = [
    'duration', 'src_bytes', 'dst_bytes', 'count',
    'diff_srv_rate', 'dst_host_diff_srv_rate', 'flag'
]

# Calculate improved thresholds
def calculate_threshold(feature, method='iqr', multiplier=1.5):
    if method == 'iqr':
        q75, q25 = np.percentile(normal_traffic[feature], [75, 25])
        iqr = q75 - q25
        return q75 + multiplier*iqr
    else:  # mean + std
        mean = normal_traffic[feature].mean()
        std = normal_traffic[feature].std()
        return mean + multiplier*std

thresholds = {
    'duration': 1000,  # Fixed based on analysis (normal mean: 168, probe mean: 2074)
    'src_bytes': 5000,  # Normal mean: 13133, probe mean: 385679
    'dst_bytes': 5000,  # Normal mean: 4329, probe mean: 181074
    'count': 40,       # Normal mean: 22, probe mean: 77
    'diff_srv_rate': 0.15,  # Normal mean: 0.03, probe mean: 0.26
    'dst_host_diff_srv_rate': 0.15,  # Normal mean: 0.04, probe mean: 0.40
    'flag_suspicious': ['SF', 'REJ', 'RSTR', 'SH', 'S0']  # Suspicious flags
}

print("Optimized Probe Detection Thresholds:")
for k, v in thresholds.items():
    if k != 'flag_suspicious':
        print(f"{k}: {v:.2f}")

# Enhanced probe detection with risk scoring
def detect_probe(row):
    risk_score = 0
    
    # Pattern 1: Short duration with high byte count
    if row['duration'] < thresholds['duration']:
        if row['src_bytes'] > thresholds['src_bytes']:
            risk_score += 2
        if row['dst_bytes'] > thresholds['dst_bytes']:
            risk_score += 2
    
    # Pattern 2: High connection count with service diversity
    if row['count'] > thresholds['count']:
        risk_score += 1
        if row['diff_srv_rate'] > thresholds['diff_srv_rate']:
            risk_score += 1
        if row['dst_host_diff_srv_rate'] > thresholds['dst_host_diff_srv_rate']:
            risk_score += 1
    
    # Pattern 3: Suspicious flag patterns
    if row['flag'] in thresholds['flag_suspicious']:
        risk_score += 2
        if row['flag'] in ['REJ', 'RSTR']:  # Particularly suspicious flags
            risk_score += 1
    
    # Protocol specific adjustments
    if row['protocol_type'] == 'icmp':
        if row['count'] > thresholds['count']/2:
            risk_score += 1
    
    return 1 if risk_score >= 5 else 0  # Higher threshold reduces FPs

# Apply detection
train_data['predicted_probe'] = train_data.apply(detect_probe, axis=1)

# Evaluation
print("\n Probe Detection Performance:")
print("Accuracy:", accuracy_score(train_data['is_probe'], train_data['predicted_probe']))
print("Confusion Matrix:")
print(confusion_matrix(train_data['is_probe'], train_data['predicted_probe']))
print("\nClassification Report:")
print(classification_report(train_data['is_probe'], train_data['predicted_probe']))

# Feature importance
print("\nMost Important Features for Probe Detection:")
print("1. Flag patterns (REJ/RSTR/S0 flags are strong indicators)")
print("2. High src_bytes/dst_bytes with short duration")
print("3. High diff_srv_rate combined with high count")
print("4. ICMP protocol with high connection count")