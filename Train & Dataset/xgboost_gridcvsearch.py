import pandas as pd
import pickle
import numpy as np
import logging
from sklearn.model_selection import train_test_split, GridSearchCV
from xgboost import XGBClassifier
from datetime import datetime

# === Setup Logging ===
logging.basicConfig(
    filename='grid_search_log.txt',
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

print("🔄 Memuat dataset...")
logging.info("Memuat dataset dan melakukan preprocessing")

# === Load dataset ===
df = pd.read_csv('preprocessed_output.csv')
df['label'] = df['label'].map({'ransomware': 1, 'benign': 0})
df = df.drop(columns=df.select_dtypes(include=['object']).columns.tolist())

# === Tambahkan noise is_signed & is_cert_valid ===
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
                df.at[idx, cert_column] = rng.integers(0, 2)
            else:
                df.at[idx, cert_column] = 0
    return df

df = add_signed_noise(df, 'is_signed', flip_prob=0.25, rng=rng)
df = add_cert_valid_noise(df, signed_column='is_signed', cert_column='is_cert_valid', rng=rng)

# === Pisahkan fitur dan label ===
X = df.drop(columns=['label'])
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42, )

print("✅ Dataset siap untuk training.")
logging.info("Dataset selesai diproses dan dibagi ke training/testing.")

# === Grid parameter lengkap ===
param_grid = {
    'max_depth': [7, 8, 9],
    'learning_rate': [0.07, 0.75, 0.08],
    'n_estimators': [500, 800, 1000],
    'gamma': [0.5, 0.55, 0.6],
    'reg_alpha': [0.6, 0.65, 0.7],
    'reg_lambda': [0.7, 0.75, 0.8]
}

print("🚀 Memulai proses Grid Search CV (bisa memakan waktu lama)...")
logging.info("Grid Search CV dimulai dengan parameter grid total %d kombinasi", 
             np.prod([len(v) for v in param_grid.values()]))

# === Inisialisasi XGBoost dengan GPU ===
model = XGBClassifier(
    device = "cuda",       # aktifkan GPU
    tree_method='hist',
    eval_metric='logloss',
    random_state=42,
    early_stopping_rounds=15
)

grid_search = GridSearchCV(
    estimator=model,
    param_grid=param_grid,
    scoring='f1',
    cv=5,
    verbose=2,
    n_jobs=-1
)

input("lanjut? (enter untuk melanjutkan)")

# === Mulai training ===
start_time = datetime.now()
grid_search.fit(X_train, y_train, eval_set=[(X_test, y_test)])
end_time = datetime.now()

print("✅ Grid Search selesai!")
print("🕒 Total waktu training:", end_time - start_time)
logging.info("Grid Search selesai. Durasi: %s", str(end_time - start_time))

# === Tampilkan hasil terbaik ===
print("📌 Best Parameters:", grid_search.best_params_)
print("📈 Best Score (F1):", grid_search.best_score_)
logging.info("Best Parameters: %s", str(grid_search.best_params_))
logging.info("Best Score (F1): %.4f", grid_search.best_score_)

# === Simpan model terbaik ===
best_model = grid_search.best_estimator_
with open('ransompyshield_best.pkl', 'wb') as f:
    pickle.dump(best_model, f)
print("✅ Best model saved as 'ransompyshield_best.pkl'")
logging.info("Model terbaik disimpan sebagai 'ransompyshield_best.pkl'")
