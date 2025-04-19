import pandas as pd

def preprocess_blint(csv_path, output_path="preprocessed_output.csv"):
    df = pd.read_csv(csv_path)

    # Fix NaN
    df['blint_findings'] = df['blint_findings'].fillna("")

    # Parse semua flags dari kolom blint_findings
    all_flags = set()
    for findings in df['blint_findings']:
        flags = [f.strip() for f in findings.split(",") if f.strip()]
        all_flags.update(flags)

    all_flags = sorted(all_flags)

    for flag in all_flags:
        col_name = f'blint_{flag.lower().replace(" ", "_")}'
        df[col_name] = df['blint_findings'].apply(
            lambda x: 1 if flag in x else 0
        )

    # Drop the unused parsed flags (Change as you need)
    columns_to_drop = [
        'imported_dlls',
        'blint_dll',
        'blint_blint_error',
        'blint_blint_timeout',
        'blint_executable_image',
        'blint_need_32bit_machine',
        'blint_force_integrity',
        'blint_large_address_aware',
        'blint_appcontainer',
        'blint_bytes_reversed_lo',
        'blint_bytes_reversed_hi',
        'blint_no_isolation',
        'blint_net_run_from_swap',
        'blint_removable_run_from_swap',
        'blint_terminal_server_aware',
        'blint_dynamic_base',
        'blint_wdm_driver',
        'blint_local_syms_stripped',
        'blint_line_nums_stripped',
        'blint_debug_stripped',
        'blint_relocs_stripped',
    ]
    df.drop(columns=[col for col in columns_to_drop if col in df.columns], inplace=True)
    df.drop(columns=['blint_findings'], inplace=True)

    df.to_csv(output_path, index=False)
    print(f"[INFO] Preprocessed dataset saved to: {output_path}")

preprocess_blint("output.csv")