import os.path
import time
import asyncio
import joblib
import matplotlib
import pandas as pd
from sklearn.model_selection import GridSearchCV

from backend.utils import is_suspicious

matplotlib.use('TkAgg')

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

from win10toast import ToastNotifier
from PIL import Image

MODEL_PATH = "./model/model.pkl"
DATA_PATH = "data/packets.csv"
TRAINING_DATA_PATH = "data/labeled.csv"


def label_data(df):
    df['Suspicious'] = df.apply(is_suspicious, axis=1)
    return df


def clean_data(df):
    print("\n Before Cleaning: ")
    print(df.columns)
    df_clean = df.drop(columns=['Source', 'Destination', 'Info', 'Protocol', 'No.', 'Time'], errors='ignore')
    df_clean.dropna(inplace=True)

    print("\n After Cleaning: ")
    print(df_clean.head())
    return df_clean


def train_and_evaluate(df):
    print("\n Training Model...")

    # == Preprocessing ==
    X = df.drop('Suspicious', axis=1)
    y = df['Suspicious']

    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.3, random_state=42)

    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
        'max_features': ['sqrt', 'log2'],
    }

    # == Training ==
    grid_search = GridSearchCV(RandomForestClassifier(), param_grid, cv=5, scoring="accuracy", n_jobs=-1)
    grid_search.fit(X_train, y_train)

    # model predictions
    best_model = grid_search.best_estimator_
    y_pred = best_model.predict(X_test)

    print("\nModel Performance:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print(confusion_matrix(y_test, y_pred))
    print(f"f1 score: {f1_score(y_test, y_pred)}")
    print(classification_report(y_test, y_pred))

    # save model to pkl file
    joblib.dump(best_model, "./model/model.pkl")
    print(f"Model saved to model/model.pkl")


def predict_packets(df):
    print("\n Making Predictions on new  dataset")

    if 'Suspicious' in df.columns:
        df = df.drop('Suspicious', axis=1, errors='ignore')
    model = joblib.load(MODEL_PATH)
    prediction = model.predict(df)
    df['Prediction'] = prediction
    df.to_csv("predictions.csv", index=False)

    return df


def main():
    print("Initializing Wireshark Plugin Suspicious Packet prediction model...")

    # if not os.path.exists(MODEL_PATH):
    #     print("No model found. Training with labeled dataset.")
    #
    #     df = pd.read_csv(TRAINING_DATA_PATH)
    #     df = label_data(df)
    #     df_clean = clean_data(df)
    #     train_and_evaluate(df_clean)

    print("\nStarting Predictions...")

    if not os.path.exists(DATA_PATH):
        print(f"No packet data found at {DATA_PATH}")
        return

    print("\nLoading new data to predict...")
    df_new = pd.read_csv(DATA_PATH)
    df_new_clean = clean_data(df_new)

    if df_new_clean.empty:
        print("No data after cleaning. Aborting...");
        return
    df_predicted = predict_packets(df_new_clean)

    print(df_predicted)

    # # when making predictions if a value is predicted as sus then it should send an alert
    # for index, row in df_predicted.iterrows():
    #
    #     if int(row["Prediction"]) == 1:
    #         print()

if __name__ == "__main__":
    main()
