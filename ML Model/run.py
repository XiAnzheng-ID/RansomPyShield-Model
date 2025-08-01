import argparse
import pickle
import os
import random
import pandas as pd
from extract import extract_pe_features, load_yara_rules

MODEL_FEATURES = [
    'number_of_sections', 
    'entry_point', 
    'dll_characteristics', 
    'Check_for_Debugger', 
    'C2_indicator', 
    'ConventionEngine_indicator', 
    'contain_crypto_address', 
    'suspicious_imphash', 
    'is_packed', 
    'ransomware_command_indicator', 
    'suspicious_technique_indicator', 
    'contain_tor_link', 
    'using_encryption_library', 
    'ransomware_string_indicator', 
    'cmd_powershell_usage_indicator', 
    'suspicious_entropy_and_indicator', 
    'yaraify_indicator', 
    'yara_match_count', 
    'unique_section_names', 
    'max_entropy', 
    'min_entropy', 
    'mean_entropy', 
    'SectionsMinRawsize', 
    'SectionMaxRawsize', 
    'SectionsMeanRawsize', 
    'SectionsMinVirtualsize', 
    'SectionMaxVirtualsize', 
    'SectionsMeanVirtualsize', 
    'imported_dll_count', 
    'imported_function_count', 
    'exported_function_count'
]

# Scanned Extension
ALLOWED_EXTENSIONS = ('.exe', '.EXE', '.dll', '.DLL', '.pyd', '.PYD', '.ransom', '.malware', '.mal', '.virus')

def interpret_probability(probability, diff_threshold=0.15):
    prob_benign = probability[0]
    prob_ransom = probability[1]
    diff = abs(prob_benign - prob_ransom)

    if diff <= diff_threshold:
        return "Unknown/Suspicious"
    elif prob_ransom > prob_benign:
        return "Ransomware/Malware"
    else:
        return "Benign"

def scan_file(file_path, model, yara_rules, noise_features=None):
    # 1. Ekstraksi fitur PE standar
    features = extract_pe_features(file_path, yara_rules, label="unknown")
    if not features:
        print(f"[ERROR] Failed to Extract {file_path}")
        return

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

    return prediction, probability, verdict

#run.py --folder "Path\To\Folder" --model "model.pkl" --yara_rules "Path\To\YaraRules" --blint --label benign/ransomware"
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="Scan a file")
    parser.add_argument("--folder", help="Scan all file on a directory")
    parser.add_argument("--model", required=True, help="ML Model")
    parser.add_argument("--yara_rules", required=True, help="yara folder")
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
    misclassified_files = []
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
                        else:
                            misclassified_files.append(full_path)
                            print(f"[MISCLASSIFIED] {full_path} predicted as {verdict}")

        print(f"\n[SUMMARY] Total scanned files: {total}")
        if ground_truth_label is not None:
            accuracy = (correct / total) * 100 if total > 0 else 0
            print(f"[SUMMARY] Accuracy based on test ({args.label}): {accuracy:.2f}%")
        print("[SUMMARY] Verdict counts:")
        for v, c in verdict_counts.items():
            print(f"  {v} : {c}")

        if misclassified_files:
            log_path = "misclassified_log.txt"
            with open(log_path, "w") as log_file:
                for file in misclassified_files:
                    log_file.write(file + "\n")
            print(f"[SUMMARY] Misclassified files saved to {log_path}")
        else:
            print("[SUMMARY] No misclassified files.")

if __name__ == "__main__":
    main()