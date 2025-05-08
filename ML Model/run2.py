import argparse
import pickle
import os
import random
import pandas as pd
import numpy as np
from extract import extract_pe_features, load_yara_rules, extract_blint_findings, extract_sigcheck_info

MODEL_FEATURES = [
    'number_of_sections','entry_point','dll_characteristics','contain_crypto_address','is_packed',
    'ransomware_command_indicator','suspicious_technique_indicator','contain_tor_link','using_encryption_library','ransomware_string_indicator',
    'suspicious_entropy_and_indicator','Check_for_Debugger','ConventionEngine_indicator','yara_match_count','unique_section_names',
    'max_entropy','min_entropy','mean_entropy','SectionsMinRawsize','SectionMaxRawsize',
    'SectionsMeanRawsize','SectionsMinVirtualsize','SectionMaxVirtualsize','SectionsMeanVirtualsize','imported_dll_count',
    'imported_function_count','exported_function_count'
]

# Scanned Extension
ALLOWED_EXTENSIONS = ('.exe', '.EXE', 'dll', '.DLL', '.pyd', '.PYD', '.ransom', '.malware', '.mal', '.virus')

def parse_blint_flags(blint_output):
    # Blint output string ke set flag
    flags = set(f.strip() for f in blint_output.split(",") if f.strip())
    return flags

def interpret_probability(probability, ransomware_threshold=0.70, gray_threshold=0.50):
    prob_ransomware = probability[1]
    if prob_ransomware >= ransomware_threshold:
        return "Ransomware/Malware"
    elif prob_ransomware >= gray_threshold:
        return "Unknown/Suspicious"
    else:
        return "Benign"

def scan_file(file_path, model, yara_rules, use_blint=False, blint_path="blint.exe", use_sigcheck=False, sigcheck_path="sigcheck.exe", noise_features=None):
    # 1. Ekstraksi fitur PE standar
    features = extract_pe_features(file_path, yara_rules, label="unknown")
    if not features:
        print(f"[ERROR] Failed to Extract {file_path}")
        return

    if use_blint:
        blint_raw = extract_blint_findings(file_path, blint_path)
        blint_flags = parse_blint_flags(blint_raw)

        blint_possible_flags = [
            'BYTES_REVERSED_HI','BYTES_REVERSED_LO','DEBUG_STRIPPED','DYNAMIC_BASE','GUARD_CF',
            'HIGH_ENTROPY_VA','LARGE_ADDRESS_AWARE','LINE_NUMS_STRIPPED','LOCAL_SYMS_STRIPPED','NEED_32BIT_MACHINE',
            'NO_SEH','NX_COMPAT','RELOCS_STRIPPED','TERMINAL_SERVER_AWARE'
        ]
        for flag in blint_possible_flags:
            features[f'blint_{flag.lower()}'] = 1 if flag in blint_flags else 0
    
    if use_sigcheck:
        sigcheck_result = extract_sigcheck_info(file_path, sigcheck_path)
        features['is_signed'] = sigcheck_result.get('is_signed', 0)
        features['is_cert_valid'] = sigcheck_result.get('is_cert_valid', 0)

    if noise_features:
        for feat in noise_features:
            if feat in features:
                if isinstance(features[feat], (int, float)):
                    if random.random() < 0.5:  # 50% prob
                        original = features[feat]
                        features[feat] = 1 if features[feat] == 0 else 0
                        print(f"[NOISE] Flipped {feat}: {original} -> {features[feat]}")
                    else:
                        print(f"[NOISE] Skipped flipping {feat}")
                else:
                    print(f"[NOISE] Cannot flip non-numeric feature: {feat}")
            else:
                print(f"[NOISE] Feature '{feat}' not found in extracted features.")

    # 3. Buat DataFrame dan pastikan semua fitur model tersedia
    df = pd.DataFrame([features])
    missing = [feat for feat in MODEL_FEATURES if feat not in df.columns]
    for m in missing:
        df[m] = 0
    df = df[MODEL_FEATURES]

    # 4. Prediksi dengan model
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]

    print(f"\n[RESULT] File: {file_path}")
    print(f"Benign                  : {probability[0]*100:.2f}%")
    print(f"Ransomware/Malware      : {probability[1]*100:.2f}%")

    # 5. Threshold analisis
    verdict = interpret_probability(probability)
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

#run.py --folder "Path\To\Folder" --model "model.pkl" --yara_rules "Path\To\YaraRules" --blint --label benign/ransomware"
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="Scan a file")
    parser.add_argument("--folder", help="Scan all file on a directory")
    parser.add_argument("--model", required=True, help="ML Model")
    parser.add_argument("--yara_rules", required=True, help="yara folder")
    parser.add_argument("--sigcheck", action="store_true", help="sign scan")
    parser.add_argument("--blint", action="store_true", help="blint scan")
    parser.add_argument("--label", type=str, choices=["benign", "ransomware"], help="Label ground truth untuk folder (benign/ransomware)")
    parser.add_argument("--add_noise", type=str, help="Fitur yang ingin di-flip, pisahkan dengan koma (contoh: is_packed,blint_no_seh,is_signed)")
    args = parser.parse_args()

    if not args.file and not args.folder:
        print("[ERROR] Please provide either --file or --folder argument")
        return
    
    noise_features = None
    if args.add_noise:
        noise_features = [feat.strip() for feat in args.add_noise.split(",") if feat.strip()]
        print(f"[INFO] Noise will be added to features: {noise_features}")

    # Load model
    with open(args.model, 'rb') as f:
        model = pickle.load(f)
    print(f"[INFO] Model loaded from {args.model}")

    # Load YARA rules
    yara_rules, _ = load_yara_rules(args.yara_rules)

    # --file 
    if args.file:
        scan_file(
            args.file,
            model,
            yara_rules,
            use_blint=args.blint,
            blint_path=args.blint_path if hasattr(args, 'blint_path') else "blint",
            use_sigcheck=args.sigcheck,
            sigcheck_path="sigcheck.exe",
            noise_features=noise_features
        )

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
                    result = scan_file(
                        full_path,
                        model,
                        yara_rules,
                        use_blint=args.blint,
                        blint_path=args.blint_path if hasattr(args, 'blint_path') else "blint",
                        use_sigcheck=args.sigcheck,
                        sigcheck_path="sigcheck.exe",
                        noise_features=noise_features
                    )
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