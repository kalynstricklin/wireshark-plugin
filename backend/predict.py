import joblib
import pandas as pd


def predict_rf(model_file, new_data, output_file):
    df = pd.read_csv(new_data)
    df_clean = df.drop(columns=['Source', 'Destination', 'Info', 'Protocol', 'No.', 'Time'], errors='ignore')

    X_new = df_clean.drop('Suspicious', axis=1, errors='ignore')
    model = joblib.load(model_file)

    predictions = model.predict(X_new)
    df['Predicted'] = predictions
    df.to_csv(output_file, index=False)
    print(f"Predictions saved to {output_file}")

if __name__ =="__main__":
    predict_rf("model/model.pkl", "new_data.csv", "predictions.csv")