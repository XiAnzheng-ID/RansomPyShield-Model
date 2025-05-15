import pandas as pd
import numpy as np
import pickle
import matplotlib.pyplot as plt
import optuna
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier

# === Load dataset ===
df = pd.read_csv('output_no-dupe.csv')
df['label'] = df['label'].map({'ransomware': 1, 'benign': 0})
drop_cols = df.select_dtypes(include=['object']).columns.tolist()
df = df.drop(columns=drop_cols)

X = df.drop(columns=['label'])
y = df['label']

# === Define Objective Function for Optuna ===
def objective(trial):
    param = {
        'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.2),
        'max_depth': trial.suggest_int('max_depth', 3, 10),
        'n_estimators': trial.suggest_int('n_estimators', 100, 1000),
        'subsample': trial.suggest_float('subsample', 0.0, 1.0),
        'colsample_bytree': trial.suggest_float('colsample_bytree', 0.0, 1.0),
        'gamma': trial.suggest_float('gamma', 0, 1.0),
        'reg_lambda': trial.suggest_float('reg_lambda', 0.1, 1.0),
        'reg_alpha': trial.suggest_float('reg_alpha', 0.1, 1.0),
        'eval_metric': 'logloss',
        'random_state': 42
    }

    kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    accs = []

    for train_idx, val_idx in kf.split(X, y):
        X_train, X_val = X.iloc[train_idx], X.iloc[val_idx]
        y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]
        model = XGBClassifier(**param)
        model.fit(X_train, y_train)
        preds = model.predict(X_val)
        accs.append(accuracy_score(y_val, preds))

    return np.mean(accs)

# === Run Optuna Study ===
print("🔎 Menjalankan Hyperparameter Tuning dengan Optuna...")
study = optuna.create_study(direction='maximize')
study.optimize(objective, n_trials=100, show_progress_bar=True)
print("✅ Selesai. Best parameters:\n", study.best_params)

# === Evaluate with Best Params ===
best_params = study.best_params
best_params.update({'eval_metric': 'logloss', 'random_state': 42})

kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
all_preds = []
all_trues = []

for fold, (train_idx, val_idx) in enumerate(kf.split(X, y), 1):
    print(f"\n🔁 Fold {fold}")
    X_train, X_val = X.iloc[train_idx], X.iloc[val_idx]
    y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]

    model = XGBClassifier(**best_params)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_val)

    all_preds.extend(y_pred)
    all_trues.extend(y_val)

    acc = accuracy_score(y_val, y_pred)
    print(f"Akurasi Fold {fold}: {acc:.4f}")

print("\n=== Hasil Akhir Cross-Validation ===")
print("Akurasi Total:", accuracy_score(all_trues, all_preds))
print("\nClassification Report:\n", classification_report(all_trues, all_preds))

# === Final Training on All Data ===
final_model = XGBClassifier(**best_params)
final_model.fit(X, y)

with open('ransompyshield.pkl', 'wb') as f:
    pickle.dump(final_model, f)
print("✅ Final Model Trained & Saved as 'ransompyshield.pkl'")

# === Feature Importance Plot ===
importances = final_model.feature_importances_
features = X.columns
feat_imp = pd.Series(importances, index=features).sort_values(ascending=False)

print("\nFeature Importance:")
print(feat_imp.head(100))

plt.figure(figsize=(10, 6))
feat_imp.head(15).plot(kind='barh')
plt.title('Top 15 Feature Importances')
plt.gca().invert_yaxis()
plt.xlabel('Importance Score')
plt.tight_layout()
plt.show()
