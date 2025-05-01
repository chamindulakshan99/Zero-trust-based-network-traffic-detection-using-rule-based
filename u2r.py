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

# Define U2R attacks (User to Root)
u2r_attacks = [
    'buffer_overflow', 'loadmodule', 'rootkit', 'perl', 'sqlattack', 'xterm', 'ps'
]
train_data['is_u2r'] = train_data['attack_type'].apply(lambda x: 1 if x in u2r_attacks else 0)

# Analyze traffic
normal_traffic = train_data[train_data['attack_type'] == 'normal']
u2r_traffic = train_data[train_data['is_u2r'] == 1]

# Feature selection based on U2R attack characteristics
u2r_features = [
    'num_failed_logins', 'logged_in', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'su_attempted', 'root_shell',
    'is_host_login', 'protocol_type', 'service'
]

# Calculate thresholds for U2R detection
thresholds = {
    'num_failed_logins': 2,  # Multiple failed login attempts
    'num_root': 1,           # Any root access
    'num_file_creations': 2, # Suspicious file creations
    'num_shells': 1,         # Any shell spawned
    'num_access_files': 5,   # Access to multiple files
    'su_attempted': 1,       # Any su attempted
    'root_shell': 1,         # Root shell obtained
    'is_host_login': 1,      # Direct host login
    'suspicious_services': ['telnet', 'ftp', 'ssh', 'shell', 'login', 'exec'],  # Services often exploited
    'protocol_type': 'tcp'   # Most U2R attacks use TCP
}

print("U2R Detection Thresholds:")
for k, v in thresholds.items():
    if isinstance(v, list):
        print(f"{k}: {', '.join(v)}")
    else:
        print(f"{k}: {v}")

# Enhanced U2R detection with privilege escalation patterns
def detect_u2r(row):
    risk_score = 0
    
    # Pattern 1: Privilege escalation indicators
    if row['num_root'] >= thresholds['num_root']:
        risk_score += 3
    if row['root_shell'] >= thresholds['root_shell']:
        risk_score += 3
    if row['su_attempted'] >= thresholds['su_attempted']:
        risk_score += 2
    
    # Pattern 2: Suspicious file/shell activity
    if row['num_file_creations'] >= thresholds['num_file_creations']:
        risk_score += 2
    if row['num_shells'] >= thresholds['num_shells']:
        risk_score += 2
    if row['num_access_files'] >= thresholds['num_access_files']:
        risk_score += 1
    
    # Pattern 3: Authentication anomalies
    if row['num_failed_logins'] >= thresholds['num_failed_logins']:
        risk_score += 1
    if row['is_host_login'] >= thresholds['is_host_login']:
        risk_score += 1
    
    # Pattern 4: Service/Protocol context
    if row['service'] in thresholds['suspicious_services']:
        risk_score += 1
    if row['protocol_type'] == thresholds['protocol_type']:
        risk_score += 1
    
    return 1 if risk_score >= 5 else 0  # Threshold balances detection and false positives

# Apply detection
train_data['predicted_u2r'] = train_data.apply(detect_u2r, axis=1)

# Evaluation
print("\nU2R Detection Performance:")
print("Accuracy:", accuracy_score(train_data['is_u2r'], train_data['predicted_u2r']))
print("Confusion Matrix:")
print(confusion_matrix(train_data['is_u2r'], train_data['predicted_u2r']))
print("\nClassification Report:")
print(classification_report(train_data['is_u2r'], train_data['predicted_u2r']))

# Feature importance
print("\nMost Important Features for U2R Detection:")
print("1. Root shell access (root_shell, num_root)")
print("2. Privilege escalation attempts (su_attempted)")
print("3. Suspicious file/shell activity (num_file_creations, num_shells)")
print("4. Authentication anomalies (num_failed_logins, is_host_login)")
print("5. Exploitable services (telnet, ftp, ssh)")