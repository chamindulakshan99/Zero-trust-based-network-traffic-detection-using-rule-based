import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load the training dataset
train_data = pd.read_csv('KDDTrain+.TXT', header=None)

# Define column names
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

# Add a label column: 0 for normal, 1 for attack
train_data['label'] = train_data['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)

# Create attack category mapping
attack_categories = {
    'normal': 'normal',
    'back': 'dos',
    'land': 'dos',
    'neptune': 'dos',
    'pod': 'dos',
    'smurf': 'dos',
    'teardrop': 'dos',
    'apache2': 'dos',
    'udpstorm': 'dos',
    'processtable': 'dos',
    'mailbomb': 'dos',
    'ipsweep': 'probe',
    'nmap': 'probe',
    'portsweep': 'probe',
    'satan': 'probe',
    'mscan': 'probe',
    'saint': 'probe',
    'buffer_overflow': 'u2r',
    'loadmodule': 'u2r',
    'perl': 'u2r',
    'rootkit': 'u2r',
    'sqlattack': 'u2r',
    'xterm': 'u2r',
    'ps': 'u2r',
    'ftp_write': 'r2l',
    'guess_passwd': 'r2l',
    'imap': 'r2l',
    'multihop': 'r2l',
    'phf': 'r2l',
    'spy': 'r2l',
    'warezclient': 'r2l',
    'warezmaster': 'r2l',
    'sendmail': 'r2l',
    'named': 'r2l',
    'snmpgetattack': 'r2l',
    'snmpguess': 'r2l',
    'xlock': 'r2l',
    'xsnoop': 'r2l',
    'worm': 'r2l',
    'httptunnel': 'r2l'
}

# Add attack category column
train_data['attack_category'] = train_data['attack_type'].map(attack_categories)

# Filter normal traffic to calculate thresholds
normal_traffic = train_data[train_data['label'] == 0]

# Set percentile value for threshold calculation
percentile_value = 98

# Calculate percentile for relevant features
threshold_src_bytes = np.percentile(normal_traffic['src_bytes'], percentile_value) 
threshold_dst_bytes = np.percentile(normal_traffic['dst_bytes'], percentile_value) 
threshold_count = np.percentile(normal_traffic['count'], percentile_value)
threshold_srv_count = np.percentile(normal_traffic['srv_count'], percentile_value)
threshold_duration = np.percentile(normal_traffic['duration'], percentile_value)
threshold_diff_srv_rate = np.percentile(normal_traffic['diff_srv_rate'], percentile_value)
threshold_dst_host_diff_srv_rate = np.percentile(normal_traffic['dst_host_diff_srv_rate'], percentile_value)
threshold_dst_host_count = np.percentile(normal_traffic['dst_host_count'], percentile_value)
threshold_serror_rate = np.percentile(normal_traffic['serror_rate'], percentile_value)
threshold_dst_host_serror_rate = np.percentile(normal_traffic['dst_host_serror_rate'], percentile_value) 
threshold_wrong_fragment = np.percentile(normal_traffic['wrong_fragment'], percentile_value)
threshold_hot = np.percentile(normal_traffic['hot'], percentile_value) 
threshold_num_failed_logins = np.percentile(normal_traffic['num_failed_logins'], percentile_value)
threshold_num_compromised = np.percentile(normal_traffic['num_compromised'], percentile_value) 
threshold_num_file_creations = np.percentile(normal_traffic['num_file_creations'], percentile_value) 
threshold_num_access_files = np.percentile(normal_traffic['num_access_files'], percentile_value)

print("Thresholds:")
print(f"src_bytes: {threshold_src_bytes}")
print(f"dst_bytes: {threshold_dst_bytes}")
print(f"count: {threshold_count}")
print(f"srv_count: {threshold_srv_count}")
print(f"duration: {threshold_duration}")
print(f"diff_srv_rate: {threshold_diff_srv_rate}")
print(f"dst_host_diff_srv_rate: {threshold_dst_host_diff_srv_rate}")
print(f"dst_host_count: {threshold_dst_host_count}")
print(f"serror_rate: {threshold_serror_rate}")
print(f"dst_host_serror_rate: {threshold_dst_host_serror_rate}")
print(f"wrong_fragment: {threshold_wrong_fragment}")
print(f"hot: {threshold_hot}")
print(f"num_failed_logins: {threshold_num_failed_logins}")
print(f"num_compromised: {threshold_num_compromised}")
print(f"num_file_creations: {threshold_num_file_creations}")
print(f"num_access_files: {threshold_num_access_files}")

# Rule for detecting DoS attacks (returns 1)
def detect_dos(row):
    if (row['src_bytes'] > threshold_src_bytes or
        row['dst_bytes'] > threshold_dst_bytes or
        row['count'] > threshold_count or
        row['srv_count'] > threshold_srv_count or
        row['serror_rate'] > threshold_serror_rate and row['dst_host_serror_rate'] > threshold_dst_host_serror_rate):
        return 1  # DoS attack
    return 0  # Not DoS

# Rule for detecting Probing attacks (returns 2)
def detect_probing(row):
    if (row['duration'] > threshold_duration or
        row['diff_srv_rate'] > threshold_diff_srv_rate or
        row['dst_host_diff_srv_rate'] > threshold_dst_host_diff_srv_rate or
        row['diff_srv_rate'] > threshold_diff_srv_rate and row['dst_host_count'] > threshold_dst_host_count):
        return 2  # Probing attack
    return 0  # Not Probing

# Rule for detecting U2R attacks (returns 3)
def detect_u2r(row):
    if (row['hot'] > threshold_hot or
        row['num_failed_logins'] > threshold_num_failed_logins or
        row['num_compromised'] > threshold_num_compromised or
        row['root_shell'] == 1 or
        row['num_file_creations'] > threshold_num_file_creations or
        row['num_access_files'] > threshold_num_access_files):
        return 3  # U2R attack
    return 0  # Not U2R

# Rule for detecting R2L attacks (returns 4)
def detect_r2l(row):
    if (row['logged_in'] == 1 and
        (row['num_failed_logins'] > threshold_num_failed_logins or
         row['num_compromised'] > threshold_num_compromised or
         row['num_access_files'] > threshold_num_access_files or
         row['count'] > threshold_count or
         row['srv_count'] > threshold_srv_count)):
        return 4  # R2L attack
    return 0  # Not R2L

# Combined detection function that returns attack type
def detect_anomaly(row):
    # Check in order of priority (if multiple rules match, the first one will be returned)
    dos_result = detect_dos(row)
    if dos_result == 1:
        return 1
    
    probing_result = detect_probing(row)
    if probing_result == 2:
        return 2
        
    u2r_result = detect_u2r(row)
    if u2r_result == 3:
        return 3
        
    r2l_result = detect_r2l(row)
    if r2l_result == 4:
        return 4
        
    return 0  # Normal

# Apply the detection function to the dataset
train_data['predicted_type'] = train_data.apply(detect_anomaly, axis=1)

# Create a mapping from attack_category to numeric values
category_mapping = {
    'normal': 0,
    'dos': 1,
    'probe': 2,
    'u2r': 3,
    'r2l': 4
}

# Create true_type column based on attack_category
train_data['true_type'] = train_data['attack_category'].map(category_mapping)

# Calculate overall accuracy
overall_accuracy = accuracy_score(
    train_data['label'], 
    train_data['predicted_type'].apply(lambda x: 0 if x == 0 else 1)
)
print(f"\nOverall Accuracy (attack vs normal): {overall_accuracy:.4f}")

# Calculate accuracy for each attack type separately
def calculate_attack_metrics(true_type, predicted_type, attack_num):
    actual_positives = (true_type == attack_num).sum()
    true_positives = ((true_type == attack_num) & (predicted_type == attack_num)).sum()
    false_positives = ((true_type != attack_num) & (predicted_type == attack_num)).sum()
    false_negatives = ((true_type == attack_num) & (predicted_type != attack_num)).sum()
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / actual_positives if actual_positives > 0 else 0
    accuracy = true_positives / actual_positives if actual_positives > 0 else 0
    
    return {
        'Attack_Type': ['DoS', 'Probing', 'U2R', 'R2L'][attack_num-1],
        'Actual_Count': actual_positives,
        'Detected_Count': true_positives,
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'False_Positives': false_positives,
        'False_Negatives': false_negatives
    }

# Calculate metrics for each attack type
attack_metrics = []
for attack_num in [1, 2, 3, 4]:
    attack_metrics.append(calculate_attack_metrics(
        train_data['true_type'], 
        train_data['predicted_type'], 
        attack_num
    ))

# Create metrics DataFrame
metrics_df = pd.DataFrame(attack_metrics)
print("\nAttack Detection Metrics:")
print(metrics_df.to_string(index=False))

# Print confusion matrix between actual and predicted attack types
print("\nConfusion Matrix (Attack Types):")
conf_matrix = confusion_matrix(
    train_data['true_type'], 
    train_data['predicted_type'], 
    labels=[0, 1, 2, 3, 4]
)
conf_matrix_df = pd.DataFrame(
    conf_matrix,
    index=['Actual Normal', 'Actual DoS', 'Actual Probe', 'Actual U2R', 'Actual R2L'],
    columns=['Pred Normal', 'Pred DoS', 'Pred Probe', 'Pred U2R', 'Pred R2L']
)
print(conf_matrix_df)

# Detailed analysis by specific attack type
detailed_analysis = train_data.groupby(['attack_type', 'attack_category']).apply(
    lambda x: pd.Series({
        'Total': len(x),
        'Correctly_Detected': sum(x['true_type'] == x['predicted_type']),
        'Detection_Rate': sum(x['true_type'] == x['predicted_type']) / len(x),
        'Detected_As': {
            0: 'Normal',
            1: 'DoS',
            2: 'Probe',
            3: 'U2R',
            4: 'R2L'
        }[x['predicted_type'].mode()[0]] if len(x) > 0 else 'None'
    })
).reset_index()

print("\nDetailed Attack Type Analysis:")
print(detailed_analysis.to_string(index=False))