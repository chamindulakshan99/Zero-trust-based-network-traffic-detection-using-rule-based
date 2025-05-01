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

# Define R2L attacks (Remote to Local)
r2l_attacks = [
    'guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster',
    'warezclient', 'spy', 'sendmail', 'named', 'snmpgetattack', 'snmpguess',
    'xlock', 'xsnoop', 'worm', 'httptunnel'
]
train_data['is_r2l'] = train_data['attack_type'].apply(lambda x: 1 if x in r2l_attacks else 0)

# Analyze traffic
normal_traffic = train_data[train_data['attack_type'] == 'normal']
r2l_traffic = train_data[train_data['is_r2l'] == 1]

# Feature selection based on R2L attack characteristics
r2l_features = [
    'duration', 'src_bytes', 'dst_bytes', 'logged_in', 'num_failed_logins',
    'num_compromised', 'num_root', 'num_file_creations', 'num_access_files',
    'is_guest_login', 'service', 'flag', 'protocol_type'
]

# Calculate thresholds for R2L detection
thresholds = {
    'duration': 0,  # Many R2L attacks are quick
    'src_bytes': 1000,  # Normal mean: 13133, R2L mean: 903
    'dst_bytes': 1000,  # Normal mean: 4329, R2L mean: 1126
    'num_failed_logins': 2,  # Multiple failed attempts
    'num_compromised': 2,  # Compromised accounts
    'num_file_creations': 1,  # Any file creation
    'num_access_files': 3,  # Multiple file accesses
    'is_guest_login': 1,  # Guest login activity
    'suspicious_services': ['ftp', 'telnet', 'smtp', 'imap', 'pop_3', 'shell', 'login'],
    'suspicious_flags': ['SF', 'REJ', 'RSTO', 'RSTR', 'SH', 'S0'],
    'protocol_type': 'tcp'  # Most R2L use TCP
}

print("R2L Detection Thresholds:")
for k, v in thresholds.items():
    if isinstance(v, list):
        print(f"{k}: {', '.join(v)}")
    else:
        print(f"{k}: {v}")

# Enhanced R2L detection with remote exploitation patterns
def detect_r2l(row):
    risk_score = 0
    
    # Pattern 1: Authentication anomalies
    if row['num_failed_logins'] >= thresholds['num_failed_logins']:
        risk_score += 2
    if row['is_guest_login'] >= thresholds['is_guest_login']:
        risk_score += 1
    if row['num_compromised'] >= thresholds['num_compromised']:
        risk_score += 2
    
    # Pattern 2: Suspicious file activity
    if row['num_file_creations'] >= thresholds['num_file_creations']:
        risk_score += 2
    if row['num_access_files'] >= thresholds['num_access_files']:
        risk_score += 1
    
    # Pattern 3: Service/Protocol context
    if row['service'] in thresholds['suspicious_services']:
        risk_score += 2
    if row['protocol_type'] == thresholds['protocol_type']:
        risk_score += 1
    
    # Pattern 4: Connection characteristics
    if row['flag'] in thresholds['suspicious_flags']:
        risk_score += 1
    if row['logged_in'] == 0 and row['dst_bytes'] > thresholds['dst_bytes']:
        risk_score += 1  # Unauthenticated but receiving data
    
    # Pattern 5: Byte transfer anomalies
    if row['src_bytes'] < 100 and row['dst_bytes'] > thresholds['dst_bytes']:
        risk_score += 2  # Small request, large response (data exfiltration)
    
    return 1 if risk_score >= 5 else 0  # Threshold balances detection and false positives

# Apply detection
train_data['predicted_r2l'] = train_data.apply(detect_r2l, axis=1)

# Evaluation
print("\nR2L Detection Performance:")
print("Accuracy:", accuracy_score(train_data['is_r2l'], train_data['predicted_r2l']))
print("Confusion Matrix:")
print(confusion_matrix(train_data['is_r2l'], train_data['predicted_r2l']))
print("\nClassification Report:")
print(classification_report(train_data['is_r2l'], train_data['predicted_r2l']))

# Feature importance
print("\nMost Important Features for R2L Detection:")
print("1. Authentication anomalies (failed_logins, guest_login)")
print("2. Suspicious services (ftp, telnet, imap)")
print("3. File activity indicators (file_creations, access_files)")
print("4. Connection flags (REJ, RSTO, SH)")
print("5. Byte transfer patterns (small request, large response)")