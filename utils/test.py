import joblib

model = joblib.load("models/isolation_forest.pkl")

print(model.feature_names_in_)