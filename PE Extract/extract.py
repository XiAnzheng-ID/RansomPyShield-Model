import os
import pefile
import pandas as pd
import argparse
from tqdm import tqdm
import yara
import sys
from collections import Counter

# List of common section names (Add as many as you need/want)
COMMON_SECTION_NAMES = {
    ".text", ".data", ".rodata", ".bss", ".plt", ".got", ".got.plt", ".symtab",
    ".dynamic", ".dynsym", ".strtab", ".dynstr", ".interp", ".rel.dyn", ".rel.plt", 
    ".rel.ro", ".reloc", ".rsrc", "e.data", "i.data" , "r.data", ".CRT", ".tls", 
    ".ctors", ".dtors",".tdata", ".tbss", ".CODE", ".init_array", ".fini_array", 
    ".preinit_array",
}

# Mapping namespace to label from yara file name provided by user
YARA_LABEL_MAPPING = {
    "AntiDebug.yar": "Check_for_Debugger",
    "auth_api.yar": "manipulate_user_auth",
    "com_base_url_mon.yar": "can_download_execute_components",
    "command_and_control.yar" : "C2_indicator",
    "ConventionEngine.yar": "ConventionEngine_indicator",
    "CryptoAddress.yar": "contain_crypto_address",
    "imphash.yar": "suspicious_imphash",
    "INDICATOR_KNOWN_PACKER.yar": "is_packed",
    "INDICATOR_SUSPICIOUS_GENRansomware.yar": "ransomware_command_indicator",
    "INDICATOR_SUSPICIOUS_MALWARE.yar": "suspicious_technique_indicator",
    "net_share_api.yar": "can_access_network_share",
    "OnionAddress.yar": "contain_tor_link",
    "RANSOMWARE_Custom.yar": "ransomware_string_indicator",
    "security_base_api.yar": "use_security_base_api",
    "shell_api.yar": "manipulates_system_shell",
    "Sus_CMD_Powershell_Usage.yar" : "cmd_powershell_usage_indicator",
    "Sus_Obf_Enc_Spoof_Hide_PE.yar": "suspicious_entropy_and_indicator",
    "win_base_api.yar": "use_win_base_api",
    "win_base_io_api.yar": "files_directories_manipulation",
    "win_base_user_api.yar": "retrieves_account_information",
    "win_crypt_api.yar" : "using_encryption_library",
    "win_http_api.yar": "use_http_services",
    "win_network_api.yar": "supports_windows_networking",
    "win_process_api.yar": "can_create_process_and_threads",
    "win_reg_api.yar": "can_manipulate_windows_registry",
    "win_sock_api.yar": "can_send_receive_data",
    "win_svc_api.yar": "can_manipulate_windows_services",
    "win_user_api.yar": "performs_gui_actions",
    "yaraify.yar" : "yaraify_indicator",
}

def load_yara_rules(yara_dir):
    if not yara_dir or not os.path.isdir(yara_dir):
        return None, {}
    
    yara_files = [os.path.join(yara_dir, f) for f in os.listdir(yara_dir) if f.endswith(".yar")]
    
    try:
        compiled = yara.compile(filepaths={os.path.basename(file): file for file in yara_files})
        return compiled, {os.path.basename(file): file for file in yara_files}
    except Exception as e:
        print(f"[FATAL] Error loading YARA rules: {e}")
        sys.exit(1) 

def scan_with_yara(file_path, yara_rules):
    if not yara_rules:
        result = {label: 0 for label in YARA_LABEL_MAPPING.values()}
        result["yara_match_count"] = 0
        return result

    try:
        matches = yara_rules.match(file_path)
        matched_labels = set()
        matched_rule_names = []  # ← nama-nama rule yang match
        yara_match_count = len(matches)

        for match in matches:
            matched_rule_names.append(match.rule)  # ← ambil nama rule-nya
            namespace = match.namespace
            if namespace in YARA_LABEL_MAPPING:
                matched_labels.add(YARA_LABEL_MAPPING[namespace])

        result = {}
        for label in YARA_LABEL_MAPPING.values():
            result[label] = 1 if label in matched_labels else 0

        result["yara_match_count"] = yara_match_count
        return result

    except Exception as e:
        print(f"[YARA Error] {file_path}: {e}")
        result = {label: 0 for label in YARA_LABEL_MAPPING.values()}
        result["yara_match_count"] = 0
        return result

def calculate_chi2(data: bytes):
    if not data:
        return 0.0
    total = len(data)
    expected = total / 256.0
    counts = Counter(data)
    chi2 = sum(((counts.get(i, 0) - expected) ** 2) / expected for i in range(256))
    return chi2

def extract_pe_features(file_path, yara_rules, label):
    try:
        pe = pefile.PE(file_path)
        features = {
            "label": label,
            "number_of_sections": len(pe.sections),
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        }

        if yara_rules:
            yara_result = scan_with_yara(file_path, yara_rules)
            features.update(yara_result)

        section_names = [section.Name.decode("utf-8", errors="ignore").strip('\x00') for section in pe.sections]
        unique_section_count = sum(1 for name in section_names if name not in COMMON_SECTION_NAMES)
        section_entropies = [section.get_entropy() for section in pe.sections]
        raw_sizes = [section.SizeOfRawData for section in pe.sections]
        virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]

        # Chi2 per-section
        chi2_values = []
        for section in pe.sections:
            data = section.get_data()
            chi2_values.append(calculate_chi2(data))

        # Chi2 global (pakai seluruh file binary)
        with open(file_path, "rb") as f:
            file_data = f.read()
        chi2_file = calculate_chi2(file_data)

        features["unique_section_names"] = unique_section_count
        features["max_entropy"] = max(section_entropies) if section_entropies else 0
        features["min_entropy"] = min(section_entropies) if section_entropies else 0
        features["mean_entropy"] = sum(section_entropies) / len(section_entropies) if section_entropies else 0

        features["SectionsMinRawsize"] = min(raw_sizes) if raw_sizes else 0
        features["SectionMaxRawsize"] = max(raw_sizes) if raw_sizes else 0
        features["SectionsMeanRawsize"] = sum(raw_sizes) / len(raw_sizes) if raw_sizes else 0

        features["SectionsMinVirtualsize"] = min(virtual_sizes) if virtual_sizes else 0
        features["SectionMaxVirtualsize"] = max(virtual_sizes) if virtual_sizes else 0
        features["SectionsMeanVirtualsize"] = sum(virtual_sizes) / len(virtual_sizes) if virtual_sizes else 0

        features["chi2_max"] = max(chi2_values) if chi2_values else 0
        features["chi2_min"] = min(chi2_values) if chi2_values else 0
        features["chi2_mean"] = sum(chi2_values) / len(chi2_values) if chi2_values else 0
        features["chi2_global"] = chi2_file 

        imported_dlls = []
        imported_functions = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_dlls.append(entry.dll.decode(errors='ignore'))
                for imp in entry.imports:
                    if imp.name:
                        imported_functions.append(imp.name.decode(errors='ignore'))

        features["imported_dll_count"] = len(imported_dlls)
        features["imported_function_count"] = len(imported_functions)

        exported_functions = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exported_functions.append(exp.name.decode(errors='ignore'))

        features["exported_function_count"] = len(exported_functions)

        pe.close()
        return features
    except Exception as e:
        print(f"[ERROR] Failed processing {file_path}: {e}")
        return None

#Add your Custom File Extension here
def process_directory(directory, yara_rules, label):
    data = []
    if directory and os.path.isdir(directory):
        file_list = [f for f in os.listdir(directory) if f.endswith((".exe", ".EXE", ".dll", ".DLL", ".msi", ".MSI", ".ransom", ".malware", ".mal", ".virus",))]
        for file_name in tqdm(file_list, desc=f"Processing {label} files"):
            file_path = os.path.join(directory, file_name)
            print(f" Extracting: {file_name}")
            
            features = extract_pe_features(file_path, yara_rules, label)
            if features:
                data.append(features)
    return data

# example : script.py --ransomware "C:\path\to\sample" --benign "C:\path\to\benign" --yara_rules "C:\path\to\yara_rules"
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ransomware", help="Malware Sample Directory", required=True)
    parser.add_argument("--benign", help="Benign Sample Directory", required=True)
    parser.add_argument("--output", help="Define CSV filename (Default: output.csv)", default="output.csv")
    parser.add_argument("--yara_rules", help="YARA rules Directory (Optional)", default=None)
    args = parser.parse_args()
    
    if args.yara_rules:
        print("[INFO] YARA is enabled. Path:", args.yara_rules)
    else:
        print("[INFO] Yara is disabled.")

    yara_rules, yara_file_map = load_yara_rules(args.yara_rules)

    #Change the label here
    ransomware_data = process_directory(args.ransomware, yara_rules, "ransomware")
    benign_data = process_directory(args.benign, yara_rules, "benign")

    #Output Process
    df = pd.DataFrame(ransomware_data + benign_data)

    cols = [col for col in df.columns]
    df = df[cols]
    drop_if_all_values = ["No match", "No YARA rules provided"]

    for col in df.columns:
        if df[col].nunique() == 1 and df[col].iloc[0] in drop_if_all_values:
            print(f"[INFO] Skipping unused feature column: {col}")
            df.drop(columns=[col], inplace=True)

    df.to_csv(args.output, index=False)
    print(f"Dataset Saved at: {args.output}")