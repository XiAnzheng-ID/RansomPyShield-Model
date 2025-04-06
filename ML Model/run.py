import argparse
import pickle
import pandas as pd
import numpy as np
import os
from extract import extract_pe_features, load_yara_rules

MODEL_FEATURES = [
    'file_size', 'number_of_sections', 'entry_point', 'image_base', 'subsystem',
    'dll_characteristics', 'contain_bitcoin_address', 'is_packed',
    'ransomware_command_indicator', 'suspicious_technique_indicator', 'contain_monero_address',
    'contain_onion_address', 'using_encryption_library', 'ransomware_string_indicator',
    'suspicious_entropy_and_indicator', 'yara_match_count', 'unique_section_names',
    'max_entropy', 'min_entropy', 'mean_entropy', 'imported_dll_count',
    'imported_function_count', 'exported_function_count'
]

# Scanned Extension
ALLOWED_EXTENSIONS = ('.exe', '.dll', '.EXE', '.DLL', '.ransom', '.malware', '.mal', '.virus')

def scan_file(file_path, model, yara_rules):
    features = extract_pe_features(file_path, yara_rules, label="unknown")
    if not features:
        print(f"[ERROR] Gagal mengekstrak fitur dari {file_path}")
        return

    df = pd.DataFrame([features])
    missing = [feat for feat in MODEL_FEATURES if feat not in df.columns]
    for m in missing:
        df[m] = 0
    df = df[MODEL_FEATURES]

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]
    label_map = {0: "Benign", 1: "Ransomware/Malware"}

    print(f"\n[RESULT] File: {file_path}")
    print(f"Benign                  : {probability[0]*100:.2f}%")
    print(f"Ransomware/Malware      : {probability[1]*100:.2f}%")

    #Different Threshold Count
    diff = abs(probability[0] - probability[1])
    if diff <= 0.10:
        verdict = "Unknown/Suspicious"
    else:
        verdict = label_map[prediction]
    print(f"Verdict                 : {verdict}")

    #Check for feature importance
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        top_n = 10
        sorted_idx = np.argsort(importances)[::-1][:top_n]

        print(f"[INFO] Top {top_n} features contributing to prediction:")
        for idx in sorted_idx:
            fname = MODEL_FEATURES[idx]
            fvalue = df.iloc[0][fname]
            print(f"- {fname} = {fvalue} (importance: {importances[idx]:.4f})")
    else:
        print("[WARNING] Model tidak memiliki feature_importances_")
    return prediction, probability, verdict     # Return prediction and confidence

#run.py --folder "E:\Dataset\Random\Malware" --model "ransompyshield.pkl" --yara_rules "D:\Kuliah\Code\Skripsi\Rule --label benign/ransomware"
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="Scan a file")
    parser.add_argument("--folder", help="Scan all file on a directory")
    parser.add_argument("--model", required=True, help="ML Model")
    parser.add_argument("--yara_rules", required=True, help="yara folder")
    parser.add_argument("--label", type=str, choices=["benign", "ransomware"], help="Label ground truth untuk folder (benign/ransomware)")
    args = parser.parse_args()

    if not args.file and not args.folder:
        print("[ERROR] Please provide either --file or --folder argument")
        return

    # Load model
    with open(args.model, 'rb') as f:
        model = pickle.load(f)
    print(f"[INFO] Model loaded from {args.model}")

    # Load YARA rules
    yara_rules, _ = load_yara_rules(args.yara_rules)

    # --file 
    if args.file:
        scan_file(args.file, model, yara_rules)

    if args.folder:
        print(f"[INFO] Scanning folder: {args.folder}")
        total = 0
        correct = 0
        verdict_counts = {"Benign": 0, "Ransomware/Malware": 0, "Unknown/Suspicious": 0}

        ground_truth_label = None
        if args.label:
            ground_truth_label = 0 if args.label.lower() == "benign" else 1

        for root, _, files in os.walk(args.folder):
            for filename in files:
                if filename.lower().endswith(ALLOWED_EXTENSIONS):
                    full_path = os.path.join(root, filename)
                    result = scan_file(full_path, model, yara_rules)
                    if result is None:
                        continue

                    prediction, _, verdict = result
                    total += 1
                    verdict_counts[verdict] += 1

                    if ground_truth_label is not None and verdict in ["Benign", "Ransomware/Malware"]:
                        if prediction == ground_truth_label:
                            correct += 1

        print(f"\n[SUMMARY] Total scanned files: {total}")
        if ground_truth_label is not None:
            accuracy = (correct / total) * 100 if total > 0 else 0
            print(f"[SUMMARY] Accuracy based on ground truth ({args.label}): {accuracy:.2f}%")
        print("[SUMMARY] Verdict counts:")
        for v, c in verdict_counts.items():
            print(f"  {v} : {c}")

if __name__ == "__main__":
    main()
