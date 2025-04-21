import os.path
import getopt, sys

import joblib
import pandas as pd

MODEL_PATH = "./model/model.pkl"
DATA_PATH = "data/packets1.csv"
PREDICTED_OUT_PATH = "predictions/predictions.csv"

# load pre-trained model
model = joblib.load(MODEL_PATH)

last_timestamp = 0


def clean_data(df):
    print("=== Cleaning Data ===")
    print(df.columns)
    df_clean = df.drop(columns=['Source', 'Destination', 'Protocol', 'Info', 'No.'], errors='ignore')

    # protocol  tcp=0, udp=1, dns=2
    df_clean['Protocol_Code'] = df['Protocol'].astype('category').cat.codes
    protocol_map = dict(enumerate(df['Protocol'].astype('category').cat.categories))
    print(protocol_map)

    # flag SYN, ACK using info column
    df_clean['flag_rst_ack'] = df['Info'].str.contains(r'\[rst, ack\]', case=False, na=False).astype(int)
    df_clean['flag_syn'] = df['Info'].str.contains(r'\[syn\]', case=False, na=False).astype(int)

    # Add a column to calculate the time between the previous packet and the next packet (default is previous packet)
    if 'Time' in df_clean.columns:
        df_clean['Time'] = pd.to_numeric(df_clean['Time'], errors='coerce')
        df_clean['Time_Delta'] = df_clean['Time'].diff().fillna(0)

    df_clean.dropna(inplace=True)

    print("=== After Cleaning: ===")
    print(df_clean.head())
    return df_clean


def clean_row(df):
    # takes a row as a string? so convert it to a dataframe
    # df = pd.DataFrame([row])
    df_clean = df.drop(columns=['Source', 'Destination', 'Protocol', 'Info', 'No.'], errors='ignore')
    # add the columns
    df_clean['Protocol_Code'] = df['Protocol'].astype('category').cat.codes
    df_clean['flag_rst_ack'] = df['Info'].str.contains(r'\[rst, ack\]', case=False, na=False).astype(int)
    df_clean['flag_syn'] = df['Info'].str.contains(r'\[syn\]', case=False, na=False).astype(int)
    df_clean['Time'] = pd.to_numeric(df['Time'], errors='coerce')
    # use global last time from previous packet to calculate the time delta
    df_clean['Time_Delta'] = df_clean['Time'] - last_timestamp

    update_timestamp(df_clean)
    df_clean.dropna(inplace=True)
    return df_clean


def update_timestamp(df_clean):
    global last_timestamp
    last_timestamp = df_clean['Time']


def predict_rt(row):
    print("Starting Real-Time prediction...")

    # clean row (cannot do change in time between packets because only 1 row)
    df_clean = clean_row(row)
    print("rt clean", df_clean)
    if not df_clean.empty:
        prediction = model.predict(df_clean)[0]
        print(f"RT Prediction: {prediction}")


def predict_packets(df):
    print("=== Starting Batch File Predictions ===")

    if 'Suspicious' in df.columns:
        df = df.drop('Suspicious', axis=1, errors='ignore')

    prediction = model.predict(df)
    df['Prediction'] = prediction
    df.to_csv(PREDICTED_OUT_PATH, index=True)
    print(f"Predictions saved to {PREDICTED_OUT_PATH}")
    return df


# param = mode
# need to get real time to do a loop.....
# def main():


def main():
    args_length = len(sys.argv)
    args_list = sys.argv[1:]

    if args_length == 1:
        print("Please enter a command line argument")
        sys.exit(0)

    options = "rf:"

    long_options = ["realtime", "file="]

    try:
        opts, args = getopt.getopt(args_list, options, long_options)

        for opt, arg in opts:
            if opt in ("-r", "--realtime"):
                df = pd.DataFrame(data=None, columns=['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

                while (True):
                    packet = input()

                    # packet = "9,2.003091,10.0.0.45,224.0.0.22,IGMPv3,54,Membership Report / Join group 224.0.0.251 for any sources"

                    item = packet.split(",")
                    print(item)
                    df.loc[0, 'No.'] = item[0]
                    df.loc[0, 'Time'] = item[1]
                    df.loc[0, 'Source'] = item[2]
                    df.loc[0, 'Destination'] = item[3]
                    df.loc[0, 'Protocol'] = item[4]
                    df.loc[0, 'Length'] = item[5]
                    df.loc[0, 'Info'] = item[6]

                    predict_rt(df)
            elif opt in ("-f", "--file"):
                if not os.path.exists(arg):
                    print(f"No packet data found at {arg}")
                    return

                df = pd.read_csv(arg)
                df_clean = clean_data(df)

                if df_clean.empty:
                    print("No usable data after cleaning.")
                    return

                df_predicted = predict_packets(df_clean)
                print(df_predicted)
    except getopt.error as err:
        print(str(err))


if __name__ == "__main__":
    main()
