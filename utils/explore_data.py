import pandas as pd

df = pd.read_csv("data/raw/combined_logs.csv")

df.columns = df.columns.str.strip()

print("="*60)
print("DATASET INFORMATION")
print("="*60)

print("\nShape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nAttack Labels:")
print(df["Label"].value_counts())