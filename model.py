import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

def train():
    # Load dataset
    csv_path = "phishing.csv"
    if not os.path.exists(csv_path):
        print("Dataset not found. Please run generate_data.py first.")
        return

    data = pd.read_csv(csv_path)

    # Features and labels
    X = data.drop("label", axis=1)
    y = data["label"]

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Train model
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print(f"Model Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # Save model
    if not os.path.exists("saved_model"):
        os.makedirs("saved_model")
        
    joblib.dump(model, "saved_model/model.pkl")
    print("Model Saved Successfully at 'saved_model/model.pkl'")

if __name__ == "__main__":
    train()
