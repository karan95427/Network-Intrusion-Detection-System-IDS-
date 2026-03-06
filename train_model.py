import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate",
    "srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"
]

data = pd.read_csv("KDDTrain+.txt", names=columns, sep=",")

# FIX: Use a separate LabelEncoder instance for each column.
# Using a single shared encoder caused earlier columns to remain
# as raw strings (e.g. "tcp"), because fit_transform() on the next
# column would overwrite the encoder's state without re-encoding prior columns.
categorical_columns = ["protocol_type", "service", "flag", "label"]
encoders = {}
for column in categorical_columns:
    le = LabelEncoder()
    data[column] = le.fit_transform(data[column])
    encoders[column] = le  # Save encoders if needed for inference later

X = data.drop("label", axis=1)
y = data["label"]

# Safely convert to numeric, coercing any unexpected strings to NaN
X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("Accuracy:", accuracy * 100)

joblib.dump(model, "model.pkl")
joblib.dump(encoders, "encoders.pkl")  # Save encoders for use during inference

print("Model saved as model.pkl")
print("Encoders saved as encoders.pkl")