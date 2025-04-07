import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier
import matplotlib.pyplot as plt

# === Load dataset ===
df = pd.read_csv('output.csv') 

# === Encode label ===
df['label'] = df['label'].map({'ransomware': 1, 'benign': 0})

# === Drop non-numeric columns ===
drop_cols = df.select_dtypes(include=['object']).columns.tolist()
df = df.drop(columns=drop_cols)

# === Separate features and labels ===
X = df.drop(columns=['label'])
y = df['label']

# === Split data ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# === Training model ===
model = XGBClassifier(use_label_encoder=False, eval_metric='logloss')
model.fit(X_train, y_train)

# === Evaluate ===
y_pred = model.predict(X_test)
print("Akurasi:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# === save model ===
with open('ransompyshield.pkl', 'wb') as f:
    pickle.dump(model, f)
print("✅ Model Saved as 'ransompyshield.pkl'")

# === Feature Importance ===
importances = model.feature_importances_
features = X.columns
feat_imp = pd.Series(importances, index=features).sort_values(ascending=False)

print("\nFeature Importance:")
print(feat_imp.head(15))

plt.figure(figsize=(15, 6))
feat_imp.head(15).plot(kind='barh')
plt.title('Top 15 Feature Importances')
plt.gca().invert_yaxis()
plt.xlabel('Importance Score')
plt.tight_layout()
plt.show()
