import argparse
import pickle
import pandas as pd
import numpy as np
import os
from extract import extract_pe_features, load_yara_rules, extract_blint_findings

MODEL_FEATURES = [
    'file_size','number_of_sections','file_characteristics','dll_characteristics',
    'size_of_image','size_of_headers','size_of_code','Check_for_Debugger',
    'contain_bitcoin_address','is_packed','ransomware_command_indicator','suspicious_technique_indicator',
    'contain_monero_address','contain_onion_address','using_encryption_library','ransomware_string_indicator',
    'suspicious_entropy_and_indicator','yara_match_count','unique_section_names','max_entropy','min_entropy',
    'mean_entropy','max_section_size','min_section_size','mean_section_size',
    'is_gui','imported_dll_count','imported_function_count','exported_function_count',

    #blint
    'blint_debug_stripped','blint_guard_cf','blint_high_entropy_va','blint_line_nums_stripped',
    'blint_local_syms_stripped','blint_no_seh','blint_nx_compat','blint_relocs_stripped',
]

# Scanned Extension
ALLOWED_EXTENSIONS = ('.exe', '.dll', '.EXE', '.DLL', '.ransom', '.malware', '.mal', '.virus')

def parse_blint_flags(blint_output):
    # Blint output string ke set flag
    flags = set(f.strip() for f in blint_output.split(",") if f.strip())
    return flags

def scan_file(file_path, model, yara_rules, use_blint=False, blint_path="blint"):
    # 1. Ekstraksi fitur PE standar
    features = extract_pe_features(file_path, yara_rules, label="unknown")
    if not features:
        print(f"[ERROR] Gagal mengekstrak fitur dari {file_path}")
        return

    if use_blint:
        blint_raw = extract_blint_findings(file_path, blint_path)
        blint_flags = parse_blint_flags(blint_raw)

        blint_possible_flags = [
            "DEBUG_STRIPPED", "GUARD_CF", "HIGH_ENTROPY_VA", "LINE_NUMS_STRIPPED", 
            "LOCAL_SYMS_STRIPPED", "NO_SEH", "NX_COMPAT", "RELOCS_STRIPPED",
        ]
        for flag in blint_possible_flags:
            features[f'blint_{flag.lower()}'] = 1 if flag in blint_flags else 0

    # 3. Buat DataFrame dan pastikan semua fitur model tersedia
    df = pd.DataFrame([features])
    missing = [feat for feat in MODEL_FEATURES if feat not in df.columns]
    for m in missing:
        df[m] = 0
    df = df[MODEL_FEATURES]

    # 4. Prediksi dengan model
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]
    label_map = {0: "Benign", 1: "Ransomware/Malware"}

    print(f"\n[RESULT] File: {file_path}")
    print(f"Benign                  : {probability[0]*100:.2f}%")
    print(f"Ransomware/Malware      : {probability[1]*100:.2f}%")

    # 5. Threshold analisis
    diff = abs(probability[0] - probability[1])
    verdict = "Unknown/Suspicious" if diff <= 0.10 else label_map[prediction]
    print(f"Verdict                 : {verdict}")

    # 6. Top fitur (jika model tree-based)
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        top_n = 15
        sorted_idx = np.argsort(importances)[::-1][:top_n]
        print(f"[INFO] Top {top_n} features contributing to prediction:")
        for idx in sorted_idx:
            fname = MODEL_FEATURES[idx]
            fvalue = df.iloc[0][fname]
            print(f"- {fname} = {fvalue} (importance: {importances[idx]:.4f})")
    else:
        print("[WARNING] Model missing feature_importances_")

    return prediction, probability, verdict

#run.py --folder "Path\To\Folder" --model "model.pkl" --yara_rules "Path\To\YaraRules" --label benign/ransomware"
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="Scan a file")
    parser.add_argument("--folder", help="Scan all file on a directory")
    parser.add_argument("--model", required=True, help="ML Model")
    parser.add_argument("--yara_rules", required=True, help="yara folder")
    parser.add_argument("--blint", action="store_true", help="blint scan")
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
        scan_file(args.file, model, yara_rules, use_blint=args.blint)

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
                    result = scan_file(full_path, model, yara_rules, use_blint=args.blint)
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
            print(f"[SUMMARY] Accuracy based on test ({args.label}): {accuracy:.2f}%")
        print("[SUMMARY] Verdict counts:")
        for v, c in verdict_counts.items():
            print(f"  {v} : {c}")

if __name__ == "__main__":
    main()
