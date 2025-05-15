import pandas as pd

df = pd.read_csv("output.csv")  # Ganti dengan nama file dataset kamu

# Search for duplicates
duplicates = df[df.duplicated()]

# Show Duplicate uncomment if you need it
#print("Jumlah data duplikat:", len(duplicates))
#print(duplicates)

# Delete Duplicates
df_no_duplicates = df.drop_duplicates()
print ("Total Deleted Duplicates data:", len(df_no_duplicates))
df_no_duplicates.to_csv("output_no-dupe.csv", index=False)