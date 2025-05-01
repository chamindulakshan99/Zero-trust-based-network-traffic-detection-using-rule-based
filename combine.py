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

# Define attack categories
attack_categories = {
    'normal': ['normal'],
    'probe': ['satan', 'ipsweep', 'nmap', 'portsweep', 'mscan', 'saint'],
    'dos': ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'udpstorm', 'processtable', 'mailbomb'],
    'u2r': ['buffer_overflow', 'loadmodule', 'rootkit', 'perl', 'sqlattack', 'xterm', 'ps'],
    'r2l': ['guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster', 
            'warezclient', 'spy', 'sendmail', 'named', 'snmpgetattack', 'snmpguess',
            'xlock', 'xsnoop', 'worm', 'httptunnel']
}

# Create attack category column
def get_attack_category(attack):
    for category, attacks in attack_categories.items():
        if attack in attacks:
            return category
    return 'unknown'

train_data['attack_category'] = train_data['attack_type'].apply(get_attack_category)

# Create binary columns for each attack type
for category in attack_categories:
    train_data[f'is_{category}'] = train_data['attack_type'].apply(lambda x: 1 if x in attack_categories[category] else 0)

# Separate traffic for analysis
normal_traffic = train_data[train_data['is_normal'] == 1]
probe_traffic = train_data[train_data['is_probe'] == 1]
dos_traffic = train_data[train_data['is_dos'] == 1]
u2r_traffic = train_data[train_data['is_u2r'] == 1]
r2l_traffic = train_data[train_data['is_r2l'] == 1]

# =====================================================================
# PROBE ATTACK DETECTION
# =====================================================================
probe_thresholds = {
    'duration': 1000,
    'src_bytes': 5000,
    'dst_bytes': 5000,
    'count': 40,
    'diff_srv_rate': 0.15,
    'dst_host_diff_srv_rate': 0.15,
    'flag_suspicious': ['SF', 'REJ', 'RSTR', 'SH', 'S0']
}

def detect_probe(row):
    risk_score = 0
    
    if row['duration'] < probe_thresholds['duration']:
        if row['src_bytes'] > probe_thresholds['src_bytes']: risk_score += 2
        if row['dst_bytes'] > probe_thresholds['dst_bytes']: risk_score += 2
    
    if row['count'] > probe_thresholds['count']:
        risk_score += 1
        if row['diff_srv_rate'] > probe_thresholds['diff_srv_rate']: risk_score += 1
        if row['dst_host_diff_srv_rate'] > probe_thresholds['dst_host_diff_srv_rate']: risk_score += 1
    
    if row['flag'] in probe_thresholds['flag_suspicious']:
        risk_score += 2
        if row['flag'] in ['REJ', 'RSTR']: risk_score += 1
    
    if row['protocol_type'] == 'icmp' and row['count'] > probe_thresholds['count']/2:
        risk_score += 1
    
    return 1 if risk_score >= 5 else 0

# =====================================================================
# DOS ATTACK DETECTION
# =====================================================================
def calculate_threshold(feature, method='iqr'):
    if method == 'iqr':
        q75, q25 = np.percentile(normal_traffic[feature], [75, 25])
        return q75 + 3*(q75 - q25)
    else:
        mean = normal_traffic[feature].mean()
        return mean + 2*normal_traffic[feature].std()

dos_thresholds = {
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

def detect_dos(row):
    if (row['count'] > dos_thresholds['count'] and row['src_bytes'] < dos_thresholds['src_bytes_lower']):
        return 1
    if (row['serror_rate'] > dos_thresholds['serror_rate'] and row['dst_host_serror_rate'] > dos_thresholds['dst_host_serror_rate']):
        return 1
    if (row['srv_count'] > dos_thresholds['srv_count'] and row['same_srv_rate'] < dos_thresholds['same_srv_rate']):
        return 1
    if (row['protocol_type'] in ['udp','icmp'] and row['count'] > dos_thresholds['count']/2):
        return 1
    if row['dst_bytes'] > dos_thresholds['dst_bytes']:
        return 1
    if row['diff_srv_rate'] > dos_thresholds['diff_srv_rate']:
        return 1
    return 0

# =====================================================================
# U2R ATTACK DETECTION
# =====================================================================
u2r_thresholds = {
    'num_failed_logins': 2,
    'num_root': 1,
    'num_file_creations': 2,
    'num_shells': 1,
    'num_access_files': 5,
    'su_attempted': 1,
    'root_shell': 1,
    'is_host_login': 1,
    'suspicious_services': ['telnet', 'ftp', 'ssh', 'shell', 'login', 'exec'],
    'protocol_type': 'tcp'
}

def detect_u2r(row):
    risk_score = 0
    if row['num_root'] >= u2r_thresholds['num_root']: risk_score += 3
    if row['root_shell'] >= u2r_thresholds['root_shell']: risk_score += 3
    if row['su_attempted'] >= u2r_thresholds['su_attempted']: risk_score += 2
    if row['num_file_creations'] >= u2r_thresholds['num_file_creations']: risk_score += 2
    if row['num_shells'] >= u2r_thresholds['num_shells']: risk_score += 2
    if row['num_access_files'] >= u2r_thresholds['num_access_files']: risk_score += 1
    if row['num_failed_logins'] >= u2r_thresholds['num_failed_logins']: risk_score += 1
    if row['is_host_login'] >= u2r_thresholds['is_host_login']: risk_score += 1
    if row['service'] in u2r_thresholds['suspicious_services']: risk_score += 1
    if row['protocol_type'] == u2r_thresholds['protocol_type']: risk_score += 1
    return 1 if risk_score >= 5 else 0

# =====================================================================
# R2L ATTACK DETECTION
# =====================================================================
r2l_thresholds = {
    'num_failed_logins': 2,
    'num_compromised': 2,
    'num_file_creations': 1,
    'num_access_files': 3,
    'is_guest_login': 1,
    'suspicious_services': ['ftp', 'telnet', 'smtp', 'imap', 'pop_3', 'shell', 'login'],
    'suspicious_flags': ['SF', 'REJ', 'RSTO', 'RSTR', 'SH', 'S0'],
    'protocol_type': 'tcp',
    'src_bytes': 100,
    'dst_bytes': 1000
}

def detect_r2l(row):
    risk_score = 0
    if row['num_failed_logins'] >= r2l_thresholds['num_failed_logins']: risk_score += 2
    if row['is_guest_login'] >= r2l_thresholds['is_guest_login']: risk_score += 1
    if row['num_compromised'] >= r2l_thresholds['num_compromised']: risk_score += 2
    if row['num_file_creations'] >= r2l_thresholds['num_file_creations']: risk_score += 2
    if row['num_access_files'] >= r2l_thresholds['num_access_files']: risk_score += 1
    if row['service'] in r2l_thresholds['suspicious_services']: risk_score += 2
    if row['protocol_type'] == r2l_thresholds['protocol_type']: risk_score += 1
    if row['flag'] in r2l_thresholds['suspicious_flags']: risk_score += 1
    if row['logged_in'] == 0 and row['dst_bytes'] > r2l_thresholds['dst_bytes']: risk_score += 1
    if row['src_bytes'] < r2l_thresholds['src_bytes'] and row['dst_bytes'] > r2l_thresholds['dst_bytes']: risk_score += 2
    return 1 if risk_score >= 5 else 0

# =====================================================================
# NORMAL TRAFFIC DETECTION
# =====================================================================
def detect_normal(row):
    # If none of the attacks are detected, it's normal
    if (detect_probe(row) == 0 and 
        detect_dos(row) == 0 and 
        detect_u2r(row) == 0 and 
        detect_r2l(row) == 0):
        return 1
    return 0

# =====================================================================
# APPLY DETECTION AND EVALUATE
# =====================================================================
# Apply detection functions
train_data['predicted_probe'] = train_data.apply(detect_probe, axis=1)
train_data['predicted_dos'] = train_data.apply(detect_dos, axis=1)
train_data['predicted_u2r'] = train_data.apply(detect_u2r, axis=1)
train_data['predicted_r2l'] = train_data.apply(detect_r2l, axis=1)
train_data['predicted_normal'] = train_data.apply(detect_normal, axis=1)

# Final classification
def classify_attack(row):
    if row['predicted_normal'] == 1:
        return 'normal'
    elif row['predicted_probe'] == 1:
        return 'probe'
    elif row['predicted_dos'] == 1:
        return 'dos'
    elif row['predicted_u2r'] == 1:
        return 'u2r'
    elif row['predicted_r2l'] == 1:
        return 'r2l'
    else:
        return 'unknown'

train_data['predicted_category'] = train_data.apply(classify_attack, axis=1)

# =====================================================================
# METRICS CALCULATION
# =====================================================================
def calculate_metrics(true, pred):
    cm = confusion_matrix(true, pred)
    if cm.size == 1:  # Only one class present
        tn, fp, fn, tp = 0, 0, 0, cm[0,0] if true.iloc[0] == 1 else cm[0,0]
    else:
        tn, fp, fn, tp = cm.ravel()
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    
    return {
        'Actual_Count': true.sum(),
        'Detected_Count': pred.sum(),
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'False_Positives': fp,
        'False_Negatives': fn
    }

# Calculate metrics for each attack type
metrics = {}
for category in attack_categories:
    true = train_data[f'is_{category}']
    pred = (train_data['predicted_category'] == category).astype(int)
    metrics[category] = calculate_metrics(true, pred)

# Overall accuracy (attack vs normal)
true_attack = (train_data['attack_category'] != 'normal').astype(int)
pred_attack = (train_data['predicted_category'] != 'normal').astype(int)
overall_accuracy = accuracy_score(true_attack, pred_attack)

# Confusion matrix between actual and predicted categories
conf_matrix = pd.crosstab(
    train_data['attack_category'],
    train_data['predicted_category'],
    rownames=['Actual'],
    colnames=['Predicted'],
    margins=True
)

# Detailed attack type analysis
detailed_analysis = []
for attack_type in train_data['attack_type'].unique():
    subset = train_data[train_data['attack_type'] == attack_type]
    category = get_attack_category(attack_type)
    total = len(subset)
    correctly_detected = sum(subset['predicted_category'] == category)
    detected_as = subset['predicted_category'].value_counts().idxmax() if not subset.empty else 'unknown'
    
    detailed_analysis.append({
        'attack_type': attack_type,
        'attack_category': category,
        'Total': total,
        'Correctly_Detected': correctly_detected,
        'Detection_Rate': correctly_detected / total if total > 0 else 0,
        'Detected_As': detected_as
    })

detailed_df = pd.DataFrame(detailed_analysis)

# =====================================================================
# PRINT RESULTS
# =====================================================================
print(f"\nOverall Accuracy (attack vs normal): {overall_accuracy:.4f}\n")

print("Attack Detection Metrics:")
metrics_df = pd.DataFrame(metrics).T.reset_index().rename(columns={'index': 'Attack_Type'})
print(metrics_df.to_string(index=False))

print("\nConfusion Matrix (Attack Types):")
print(conf_matrix)

print("\nDetailed Attack Type Analysis:")
print(detailed_df.to_string(index=False))