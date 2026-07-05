import pandas as pd

# Load Dataset
df = pd.read_csv("data/raw/combined_logs.csv")

# Remove extra spaces from column names
df.columns = df.columns.str.strip()

def get_total_flows():
    return len(df)

def get_normal_flows():
    return len(df[df["Label"] == "BENIGN"])


def get_attack_flows():
    return len(df[df["Label"] != "BENIGN"])

def get_attack_types():
    return df["Label"].value_counts()

def get_top_10_ports():
    return df["Destination Port"].value_counts().head(10)

def get_average_flow_duration():
    return df["Flow Duration"].mean()

def get_total_attack_categories():
    return df["Label"].nunique()


def get_dataset_summary():

    return {
        "Total Flows": get_total_flows(),
        "Normal Flows": get_normal_flows(),
        "Attack Flows": get_attack_flows(),
        "Attack Categories": get_total_attack_categories(),
        "Average Flow Duration": get_average_flow_duration()
    }