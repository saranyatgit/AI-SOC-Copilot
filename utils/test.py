model = load_model()

print("Model features:")
print(model.feature_names_in_)

print("\nCurrent features:")
print(features.columns.tolist())