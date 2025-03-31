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

# Drop the attack_type column
train_data.drop(columns=['attack_type'], inplace=True)

# Filter normal traffic to calculate thresholds
normal_traffic = train_data[train_data['label'] == 0]

# Set percentile value for threshold calculation
percentile_value = 99

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

# Rule for detecting DoS attacks
def detect_dos(row):
    if (row['src_bytes'] > threshold_src_bytes or
        row['dst_bytes'] > threshold_dst_bytes or
        row['count'] > threshold_count or
        row['srv_count'] > threshold_srv_count or
        row['serror_rate'] > threshold_serror_rate and row['dst_host_serror_rate'] > threshold_dst_host_serror_rate):
        return 1  # Possible DoS attack
    else:
        return 0  # Normal

# Rule for detecting Probing attacks
def detect_probing(row):
    if (row['duration'] > threshold_duration or
        row['diff_srv_rate'] > threshold_diff_srv_rate or
        row['dst_host_diff_srv_rate'] > threshold_dst_host_diff_srv_rate or
        row['diff_srv_rate'] > threshold_diff_srv_rate and row['dst_host_count'] > threshold_dst_host_count):
        return 1  # Possible Probing attack
    else:
        return 0  # Normal

# Rule for detecting U2R attacks
def detect_u2r(row):
    if (row['hot'] > threshold_hot or
        row['num_failed_logins'] > threshold_num_failed_logins or
        row['num_compromised'] > threshold_num_compromised or
        row['root_shell'] == 1 or
        row['num_file_creations'] > threshold_num_file_creations or
        row['num_access_files'] > threshold_num_access_files):
        return 1  # Possible U2R attack
    else:
        return 0  # Normal

# Rule for detecting R2L attacks
def detect_r2l(row):
    if (row['logged_in'] == 1 and
        (row['num_failed_logins'] > threshold_num_failed_logins or
         row['num_compromised'] > threshold_num_compromised or
         row['num_access_files'] > threshold_num_access_files or
         row['count'] > threshold_count or
         row['srv_count'] > threshold_srv_count)):
        return 1  # Possible R2L attack
    else:
        return 0  # Normal

# Rule for detecting Ipsweep attacks
def detect_ipsweep(row):
    if (row['diff_srv_rate'] > threshold_diff_srv_rate and
        row['dst_host_count'] > threshold_dst_host_count):
        return 1  # Possible Ipsweep attack
    else:
        return 0  # Normal

# Rule for detecting Neptune attacks
def detect_neptune(row):
    if (row['serror_rate'] > threshold_serror_rate and
        row['dst_host_serror_rate'] > threshold_dst_host_serror_rate):
        return 1  # Possible Neptune attack
    else:
        return 0  # Normal

# Rule for detecting Nmap attacks
def detect_nmap(row):
    if (row['duration'] > threshold_duration and
        row['dst_host_count'] > threshold_dst_host_count):
        return 1  # Possible Nmap attack
    else:
        return 0  # Normal

# Rule for detecting Teardrop attacks
def detect_teardrop(row):
    if (row['wrong_fragment'] > threshold_wrong_fragment and
        row['dst_host_count'] > threshold_dst_host_count):
        return 1  # Possible Teardrop attack
    else:
        return 0  # Normal

# Rule for detecting Warezclient attacks
def detect_warezclient(row):
    if (row['num_failed_logins'] > threshold_num_failed_logins and
        row['num_access_files'] > threshold_num_access_files):
        return 1  # Possible Warezclient attack
    else:
        return 0  # Normal

# Combined rule for detecting all attack types
def detect_anomaly(row):
    if (detect_dos(row) == 1 or
        detect_probing(row) == 1 or
        detect_u2r(row) == 1 or
        detect_r2l(row) == 1 or
        detect_ipsweep(row) == 1 or
        detect_neptune(row) == 1 or
        detect_nmap(row) == 1 or
        detect_teardrop(row) == 1 or
        detect_warezclient(row) == 1):
        return 1  # Attack
    else:
        return 0  # Normal

# Apply the detection function to the dataset
train_data['predicted_label'] = train_data.apply(detect_anomaly, axis=1)

# Calculate accuracy
accuracy = accuracy_score(train_data['label'], train_data['predicted_label'])
print(f"Accuracy: {accuracy:.2f}")

# Print classification report
print(classification_report(train_data['label'], train_data['predicted_label']))

# Print confusion matrix
cm = confusion_matrix(train_data['label'], train_data['predicted_label'])
print("Confusion Matrix:\n", cm)

# Analyze results by attack type
trainData_withAttack = pd.read_csv('KDDTrain+.TXT', header=None, names=columns)
trainData_withAttack['label'] = trainData_withAttack['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)
trainData_withAttack['PredictLabel'] = train_data['predicted_label']

attack_analysis = trainData_withAttack.groupby('attack_type').apply(
    lambda x: pd.Series({
        'Total': len(x),
        "TP+TN": sum(x['label'] == x['PredictLabel']),
        'FP': sum((x['label'] == 0) & (x['PredictLabel'] == 1)),
        'FN': sum((x['label'] == 1) & (x['PredictLabel'] == 0)),
    })
).reset_index()

print(attack_analysis)