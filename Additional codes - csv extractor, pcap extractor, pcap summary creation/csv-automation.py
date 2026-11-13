import os
import pandas as pd

def extract_packets(
    source_file: str,
    target_folder: str,
    new_file_name: str,
    packet_number_column: str,
    packet_range: tuple[int, int],
    columns_to_keep: list[str],
    separator: str = ",",
    encoding: str = "utf-8",
) -> str:

    df = pd.read_csv(source_file, sep=separator, encoding=encoding, low_memory=False)

    if packet_number_column not in df.columns:
        raise ValueError(
            f"Column '{packet_number_column}' does not exist in a file. "
            f"Available columns: {list(df.columns)}"
        )

    range_start, range_end = packet_range
    mask = df[packet_number_column].between(range_start, range_end)
    df_result = df.loc[mask].copy()

    columns = list(dict.fromkeys(columns_to_keep))
    missing = [k for k in columns if k not in df_result.columns]
    if missing:
        raise ValueError(
            f"The specified columns do not exist in the file: {missing}. "
            f"Available columns: {list(df.columns)}"
        )
    df_result = df_result[columns]

    # --- Cleaning missing data (NaN) ---
    # Empty cells are replaced with the text "N/A", so the new file has
    # a consistent structure instead of undefined NaN values.
    # Columns are first cast to the "object" type, so that inserting text
    # into a numeric column does not cause a pandas warning/error.
    df_result = df_result.astype(object)
    df_result = df_result.fillna('N/A')

    os.makedirs(target_folder, exist_ok=True)
    if not new_file_name.lower().endswith(".csv"):
        new_file_name += ".csv"
    output_path = os.path.join(target_folder, new_file_name)

    df_result.to_csv(output_path, sep=separator, encoding=encoding, index=False)

    print(f"Saved {len(df_result)} rows to: {output_path}")
    return output_path


if __name__ == "__main__":
    extract_packets(
        source_file=r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\Deauth_25.csv",
        target_folder=r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\Data for RAG tests",
        #nazwa_nowego_pliku="pakiety_550272-550278(7 pakietów).csv",
        new_file_name="second-test.csv",
        packet_number_column="frame.number",
        packet_range=(1260999, 1261573),
        columns_to_keep=["frame.time_relative", "frame.time", "wlan.bssid", "wlan.da", "wlan.fc.protected", "wlan.fc.type", "wlan.fc.subtype", "wlan.fixed.reason_code", "wlan.seq", "wlan.fc.retry", "wlan.sa", "wlan.rsn.capabilities.mfpc"],
        separator=",",
        encoding="utf-8",
    )