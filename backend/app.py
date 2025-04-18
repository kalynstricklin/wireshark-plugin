from sklearn.model_selection import GridSearchCV

import pandas as pd
import joblib
import matplotlib

from backend.utils import is_suspicious

matplotlib.use('TkAgg')

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


def label_file(csv_in, csv_out):
    df = pd.read_csv(csv_in)
    df['Suspicious'] = df.apply(is_suspicious, axis=1)
    df.to_csv(csv_out, index=False)


def train_rf(labeled_csv, model_out):
    df = pd.read_csv(labeled_csv)

    print("\n Before Cleaning: ")
    print(df[['Source', "Destination", 'Info', "Protocol", "No.", "Time"]].head())

    df_clean = df.drop(columns=['Source', 'Destination', 'Info', 'Protocol', 'No.', 'Time'], errors='ignore')

    X = df_clean.drop('Suspicious', axis=1)
    y = df_clean['Suspicious']
    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.3, random_state=42)

    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2]
    }

    grid_search = GridSearchCV(RandomForestClassifier(), param_grid, cv=5, scoring="accuracy", n_jobs=-1)
    grid_search.fit(X_train, y_train)

    best_model = grid_search.best_estimator_
    y_pred = best_model.predict(X_test)
    print("Model Performance:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    joblib.dump(best_model, model_out)


def predict_rf(model_file, new_data, output_file):
    df = pd.read_csv(new_data)
    df_clean = df.drop(columns=['Source', 'Destination', 'Info', 'Protocol', 'No.', 'Time'], errors='ignore')

    X_new = df_clean.drop('Suspicious', axis=1, errors='ignore')
    model = joblib.load(model_file)

    predictions = model.predict(X_new)
    df['Predicted'] = predictions
    df.to_csv(output_file, index=False)
    print(f"Predictions saved to {output_file}")

def main():
    print("Initializing Wireshark Plugin Suspicious Packet prediction model...")

    unlabeled_csv = "data/unlabeled.csv"

    label_file(unlabeled_csv, "data/labeled.csv")
    train_rf("data/labeled.csv", "model/model.pkl")
    predict_rf("../docs/model.pkl", "data/packets.csv", "predictions/predictions.csv")

if __name__ == "__main__":
    main()