import pandas as pd
import joblib

# Load captured packet data
def load_packet_data(path="../data/captured_packets.csv"):
    df = pd.read_csv(path)

    # Ensure columns exist (fill missing if needed)
    expected_cols = ['srcip', 'dstip', 'sport', 'dsport', 'proto', 'pktsize']
    for col in expected_cols:
        if col not in df.columns:
            df[col] = 0

    # Drop non-numeric IPs for model input (or hash them later for advanced use)
    df.drop(['srcip', 'dstip'], axis=1, inplace=True)

    # Fill any missing values
    df.fillna(0, inplace=True)

    return df

# Predict using saved model
def predict_with_model(df, model_path="../model/xgboost_classifier.pkl"):
    model = joblib.load(model_path)
    preds = model.predict(df)
    return preds

# Example usage
if __name__ == "__main__":
    df = load_packet_data()
    print("🧹 Cleaned packet data:")
    print(df.head())

    predictions = predict_with_model(df)
    print("\n🔐 Predictions (0=Benign, 1=Attack):")
    print(predictions)
