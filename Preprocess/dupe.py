import pandas as pd

# Load dataset
df = pd.read_csv("output.csv")

# Cari baris yang sepenuhnya duplikat (termasuk label)
duplicates = df[df.duplicated()]
print("Total duplikat (fitur + label):", len(duplicates))

# Hitung jumlah duplikat yang akan dihapus per label
deleted_per_label = duplicates['label'].value_counts()

# Hapus duplikat
df_no_duplicates = df.drop_duplicates()

# Info
print("Total data setelah penghapusan:", len(df_no_duplicates))
print("\nJumlah duplikat yang dihapus per label:")
print(deleted_per_label)

# Simpan hasil
df_no_duplicates.to_csv("output_no-dupe.csv", index=False)
