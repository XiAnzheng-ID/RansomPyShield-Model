import os
import pefile
import pandas as pd
import argparse
from tqdm import tqdm
import yara
import json
import subprocess
import re

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
    "BitcoinAddress.yar": "contain_bitcoin_address",
    "INDICATOR_KNOWN_PACKER.yar": "is_packed",
    "INDICATOR_SUSPICIOUS_GENRansomware.yar": "ransomware_command_indicator",
    "INDICATOR_SUSPICIOUS_MALWARE.yar": "suspicious_technique_indicator",
    "MoneroAddress.yar": "contain_monero_address",
    "OnionAddress.yar": "contain_onion_address",
    "RansomPyShield.yar": "using_encryption_library",
    "RANSOMWARE_Custom.yar": "ransomware_string_indicator",
    "Sus_Obf_Enc_Spoof_Hide_PE.yar": "suspicious_entropy_and_indicator",
}

def load_yara_rules(yara_dir):
    if not yara_dir or not os.path.isdir(yara_dir):
        return None, {}
    
    yara_files = [os.path.join(yara_dir, f) for f in os.listdir(yara_dir) if f.endswith(".yar")]
    
    try:
        compiled = yara.compile(filepaths={os.path.basename(file): file for file in yara_files})
        return compiled, {os.path.basename(file): file for file in yara_files}
    except Exception as e:
        print(f"Error loading YARA rules: {e}")
        return None, {}

def scan_with_yara(file_path, yara_rules):
    if not yara_rules:
        result = {label: 0 for label in YARA_LABEL_MAPPING.values()}
        result["yara_match_count"] = 0
        result["yara_rule_names_matched"] = ""
        return result

    try:
        matches = yara_rules.match(file_path)
        matched_labels = set()
        matched_rule_names = []  # Rule name that Match (WIP)
        yara_match_count = len(matches)

        # get the rule name that match (WIP)
        for match in matches:
            matched_rule_names.append(match.rule)  
            namespace = match.namespace
            if namespace in YARA_LABEL_MAPPING:
                matched_labels.add(YARA_LABEL_MAPPING[namespace])

        result = {}
        for label in YARA_LABEL_MAPPING.values():
            result[label] = 1 if label in matched_labels else 0

        result["yara_match_count"] = yara_match_count
        result["yara_rule_names_matched"] = ", ".join(matched_rule_names)
        return result

    except Exception as e:
        print(f"[YARA Error] {file_path}: {e}")
        result = {label: 0 for label in YARA_LABEL_MAPPING.values()}
        result["yara_match_count"] = 0
        result["yara_rule_names_matched"] = ""
        return result

def extract_capa_capabilities(file_path, capa_path="capa.exe", timeout_sec=60): #WIP
    try:
        result = subprocess.run(
            [capa_path, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            shell=False,
            timeout=timeout_sec,
            encoding="utf-8",
            errors="ignore"
        )

        output = result.stdout
        capabilities = []
        parsing_capability = False

        for line in output.splitlines():
            if "Capability" in line and "Namespace" in line:
                parsing_capability = True
                continue
            if parsing_capability:
                if line.strip() == "" or line.startswith("└") or line.startswith("╘"):
                    break
                match = re.search(r"│\s*(.+?)\s*\((\d+)\s+matches?\)\s*│", line)
                if match:
                    cap_name = match.group(1).strip()
                    match_count = int(match.group(2))
                    if match_count >= 2:
                        capabilities.append(cap_name)

        return ", ".join(capabilities) if capabilities else "No capa match"

    except subprocess.TimeoutExpired:
        print(f"[Timeout] Skipping {file_path} (capa stuck more than {timeout_sec}s)")
        return "Capa timeout"
    except Exception as e:
        print(f"[Error ] Capa: {e}")
        return "Error capa"

def extract_blint_findings(file_path, blint_path="blint", timeout_sec=60): #WIP
    try:
        result = subprocess.run(
            [blint_path, "sbom", "--stdout", "-i", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            shell=False,
            timeout=timeout_sec
        )

        output = result.stdout.strip()

        json_start = output.find('{')
        if json_start == -1:
            return "Blint Error"

        json_output = output[json_start:]

        data = json.loads(json_output)

        props = data.get("metadata", {}).get("component", {}).get("properties", [])
        char_val = ""
        dll_char_val = ""

        for prop in props:
            if prop.get("name") == "internal:characteristics":
                char_val = prop.get("value", "")
            elif prop.get("name") == "internal:dll_characteristics":
                dll_char_val = prop.get("value", "")
        
        if char_val or dll_char_val:
            return f"{char_val}, {dll_char_val}".strip(", ").strip()
        else:
            return "No blint findings"

    except subprocess.TimeoutExpired:
        print(f"[Timeout] Skipping {file_path} (blint stuck more than {timeout_sec}s)")
        return "Blint timeout"
    except Exception as e:
        print(f"[Error] blint: {e} , try to run blint manually and see if blint has errors")
        return "Blint Error"

def extract_pe_features(file_path, yara_rules, label, capa_path=None, blint_path=None):
    try:
        pe = pefile.PE(file_path)
        features = {
            "file_size": os.path.getsize(file_path),
            "number_of_sections": len(pe.sections),
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "label": label,
        }

        if yara_rules:
            yara_result = scan_with_yara(file_path, yara_rules)
            features.update(yara_result)

        if capa_path:
            features["capa_capabilities"] = extract_capa_capabilities(file_path, capa_path)

        if blint_path:
            features["blint_findings"] = extract_blint_findings(file_path, blint_path)

        section_names = [section.Name.decode("utf-8", errors="ignore").strip('\x00') for section in pe.sections]
        unique_section_count = sum(1 for name in section_names if name not in COMMON_SECTION_NAMES)
        section_entropies = [section.get_entropy() for section in pe.sections]

        features["unique_section_names"] = unique_section_count
        features["section_entropies"] = ", ".join(map(str, section_entropies))
        features["max_entropy"] = max(section_entropies) if section_entropies else 0
        features["min_entropy"] = min(section_entropies) if section_entropies else 0
        features["mean_entropy"] = sum(section_entropies) / len(section_entropies) if section_entropies else 0

        imported_dlls = []
        imported_functions = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_dlls.append(entry.dll.decode(errors='ignore'))

        features["imported_dll_count"] = len(imported_dlls)
        features["imported_function_count"] = len(imported_functions)
        features["imported_dlls"] = ", ".join(imported_dlls)

        exported_functions = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exported_functions.append(exp.name.decode(errors='ignore'))

        features["exported_function_count"] = len(exported_functions)

        pe.close()
        return features
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

#Add your Custom File Extension here
def process_directory(directory, yara_rules, label, capa_path, blint_path):
    data = []
    if directory and os.path.isdir(directory):
        file_list = [f for f in os.listdir(directory) if f.endswith((".exe", ".EXE", ".dll", ".DLL", ".ransom", ".malware", ".mal", ".virus",))]
        for file_name in tqdm(file_list, desc=f"Processing {label} files"):
            file_path = os.path.join(directory, file_name)
            print(f" Extracting: {file_name}")
            features = extract_pe_features(file_path, yara_rules, label, capa_path, blint_path)
            if features:
                data.append(features)
    return data

# example : script.py --ransomware "C:\path\to\sample" --benign "C:\path\to\benign" --yara_rules "C:\path\to\yara_rules" --capa "C:\path\to\capa.exe" --blint "C:\path\to\blint.exe"
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ransomware", help="Malware Sample Directory", required=True)
    parser.add_argument("--benign", help="Benign Sample Directory", required=True)
    parser.add_argument("-output", help="Define CSV filename (Default: output.csv)", default="output.csv")
    parser.add_argument("--yara_rules", help="YARA rules Directory (Optional)", default=None)
    parser.add_argument("--capa", nargs="?", const="default", help="Path to capa.exe (If used without value, uses ./capa.exe)")
    parser.add_argument("--blint", nargs="?", const="default", help="Path to blint.exe (If used without value, uses ./blint.exe)")

    args = parser.parse_args()
    
    if args.capa == "default":
        args.capa = os.path.join(os.getcwd(), "capa.exe")
        print("[INFO] CAPA is enabled. Path:", args.capa)
        print("[INFO] This option will slowdown the process, please be patient")
        print("[INFO] Not Recommended on a Large Dataset if you have less than 24GB Memory")

    elif args.capa is None:
        print("[INFO] Capa is Disabled.")
    else:
        print(f"[INFO] Using custom capa path: {args.capa}")

    if args.blint == "default":
        args.blint = os.path.join(os.getcwd(), "blint.exe")
        print("[INFO] blint is enabled. Path:", args.blint)
    elif args.blint is None:
        print("[INFO] Blint not used.")
    else:
        print(f"[INFO] Using custom blint path: {args.blint}")
    
    if args.yara_rules:
        print("[INFO] YARA is enabled. Path:", args.yara_rules)
    else:
        print("[INFO] Yara is disabled.")

    yara_rules, yara_file_map = load_yara_rules(args.yara_rules)

    #Change the label here
    ransomware_data = process_directory(args.ransomware, yara_rules, "ransomware", args.capa, args.blint)
    benign_data = process_directory(args.benign, yara_rules, "benign", args.capa, args.blint)

    #Output Process
    df = pd.DataFrame(ransomware_data + benign_data)

    cols = ['label'] + [col for col in df.columns if col != 'label']
    df = df[cols]
    drop_if_all_values = ["No match", "No blint findings", "No capa match", "No YARA rules provided"]

    for col in df.columns:
        if df[col].nunique() == 1 and df[col].iloc[0] in drop_if_all_values:
            print(f"[INFO] Skipping unused feature column: {col}")
            df.drop(columns=[col], inplace=True)

    df.to_csv(args.output, index=False)
    print(f"Dataset Saved at: {args.output}")