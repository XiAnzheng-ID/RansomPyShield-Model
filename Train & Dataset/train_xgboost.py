import pandas as pd
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier
import matplotlib.pyplot as plt

# === Load dataset ===
df = pd.read_csv('preprocessed_output.csv') 

# === Encode label ===
df['label'] = df['label'].map({'ransomware': 1, 'benign': 0})

# === Drop non-numeric columns ===
drop_cols = df.select_dtypes(include=['object']).columns.tolist()
df = df.drop(columns=drop_cols)

# === Add binary noise to is_signed & is_cert_valid (incase of 50% malware sample dont have a valid sign) ===
rng = np.random.default_rng(seed=42)

def add_signed_noise(df, column_name, flip_prob=0.25, rng=None):
    if column_name in df.columns and rng is not None:
        flip_mask = rng.random(len(df)) < flip_prob
        df.loc[flip_mask, column_name] = 1 - df.loc[flip_mask, column_name]
    return df

def add_cert_valid_noise(df, signed_column='is_signed', cert_column='is_cert_valid', rng=None):
    if signed_column in df.columns and cert_column in df.columns and rng is not None:
        for idx, signed in df[signed_column].items():
            if signed == 1:
                df.at[idx, cert_column] = rng.integers(0, 2)  # random 0 or 1
            else:
                df.at[idx, cert_column] = 0  # force 0 if not signed
    return df

df = add_signed_noise(df, 'is_signed', flip_prob=0.25, rng=rng)
df = add_cert_valid_noise(df, signed_column='is_signed', cert_column='is_cert_valid', rng=rng)

# === Separate features and labels ===
X = df.drop(columns=['label'])
y = df['label']

# === Split data ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, stratify=y, random_state=42
)

# === Training model ===
model = XGBClassifier(
    eval_metric='logloss',
    learning_rate=0.06,
    max_depth=5,
    n_estimators=500,
    subsample=0.8,
    colsample_bytree=0.8,
    gamma=0.5,              
    reg_lambda=0.5,        
    reg_alpha=0.5,          
    random_state=42,
    early_stopping_rounds=15,
)
model.fit(X_train, y_train, eval_set=[(X_test, y_test)])

# === Evaluate ===
y_pred = model.predict(X_test)
print("Akurasi:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# === Save model ===
with open('ransompyshield.pkl', 'wb') as f:
    pickle.dump(model, f)
print("✅ Model Saved as 'ransompyshield.pkl'")

# === Feature Importance ===
importances = model.feature_importances_
features = X.columns
feat_imp = pd.Series(importances, index=features).sort_values(ascending=False)

print("\nFeature Importance:")
print(feat_imp.head(50))

plt.figure(figsize=(50, 6))
feat_imp.head(15).plot(kind='barh')
plt.title('Top 15 Feature Importances')
plt.gca().invert_yaxis()
plt.xlabel('Importance Score')
plt.tight_layout()
plt.show()
