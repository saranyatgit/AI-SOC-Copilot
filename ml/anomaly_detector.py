import os
import joblib
import pandas as pd
import streamlit as st

from sklearn.ensemble import IsolationForest

@st.cache_data
def load_processed_data():
    data_path = "data/raw/combined_logs.csv"   # Change if your file is elsewhere
    df = pd.read_csv(data_path)
    df.columns = df.columns.str.strip()

    df = df.sample(n=1000, random_state=42)

    return df


def prepare_features(df):
    # Select only numeric columns (no .copy())
    features = df.select_dtypes(include=["number"])

    # Drop Label only if it somehow exists
    if "Label" in features.columns:
        features = features.drop(columns=["Label"])

    return features


def train_model(features):
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(features)
    return model


def predict_anomalies(model, features):
    predictions = model.predict(features)
    return predictions


def save_model(model):
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/isolation_forest.pkl")

@st.cache_resource
def load_model():
    return joblib.load("models/isolation_forest.pkl")


if __name__ == "__main__":

    df = load_processed_data()

    print("Dataset Loaded Successfully")

    features = prepare_features(df)
    print("Number of features:", len(features.columns))
    print("Current features:")
    print(features.columns.tolist())

    model = train_model(features)

    save_model(model)

    print("\nModel Saved Successfully!")

    # Load the saved model again
    model = load_model()

    print("\nModel features:")
    print(model.feature_names_in_)

    print("\nCurrent features:")
    print(features.columns.tolist())