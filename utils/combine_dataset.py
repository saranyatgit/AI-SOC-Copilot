import pandas as pd
import glob
import os

files = glob.glob("data/raw/cicids2017/*.csv")

dfs = []

for file in files:
    print(f"Loading: {os.path.basename(file)}")
    dfs.append(pd.read_csv(file))

combined_df = pd.concat(dfs, ignore_index=True)

combined_df.to_csv("data/raw/combined_logs.csv", index=False)

print("\nDataset Combined Successfully!")
print(f"Total Rows: {len(combined_df)}")
print(f"Total Columns: {len(combined_df.columns)}")