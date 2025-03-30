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
    "dst_ host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "level"
]

#fine tuning the rule based system 
mean_failed_logins = np.mean(train_data['num_failed_logins'])
std_failed_logins = np.std(train_data['num_failed_logins'])

threshold_failed_logging = mean_failed_logins + (100 * std_failed_logins)


def detect_anomaly(row):
    if row['num_failed_logins'] > threshold_failed_logging:
        return 1  # Possible brute-force attack
    elif row['src_bytes'] > 50000 and row['dst_bytes'] > 50000:
        return 1  # Possible data exfiltration
    elif row['count'] > 100 or row['srv_count'] > 50:
        return 1  # Possible DoS attack
    elif row['serror_rate'] > 0.5 or row['rerror_rate'] > 0.5:
        return 1  # Possible network scanning
    else:
        return 0  # Normal

# Apply the rule-based function
train_data['predicted_label'] = train_data.apply(detect_anomaly, axis=1)

# Calculate Accuracy
accuracy = accuracy_score(train_data['label'], train_data['predicted_label'])
print(f"Accuracy: {accuracy:.2f}")

# Print Classification Report
print(classification_report(train_data['label'], train_data['predicted_label']))

cm = confusion_matrix(train_data['label'], train_data['predicted_label'])
print("Confusion Matrix:\n", cm)


trainData_withAttack = pd.read_csv('KDDTrain+.TXT', header=None, names=columns) 
trainData_withAttack['label'] = trainData_withAttack['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)
trainData_withAttack['PredictLabel'] = train_data['predicted_label']

attack_analysis = trainData_withAttack.groupby('attack_type').apply(
    lambda x: pd.Series({
        'Total': len(x),
        "TP+TN":sum(x['label'] == x['PredictLabel']),
        'FP': sum((x['label'] == 0) & (x['PredictLabel'] == 1)),
        'FN': sum((x['label'] == 1) & (x['PredictLabel'] == 0)),
    })
).reset_index()

print(attack_analysis)