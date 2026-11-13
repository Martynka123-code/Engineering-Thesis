"""Steps 1-2: load a pcap or CSV file into a common schema.

Two functions are used from the outside:

    load_pcap("capture.pcap")        -> table in the schema
    load_csv("dataset_file.csv")     -> table in the schema

A pcap is read by tshark, and its output (CSV text) stays in memory -
no CSV file is saved (unless --save-csv was given in the terminal).

Both return a table with the same 13 fields:

    Column in the file           Field       Value type
    frame.time_epoch (pcap)
    frame.time_relative (CSV)->  ts          floating-point number
    wlan.fc.type             ->  type        integer, as in the file
    wlan.fc.subtype          ->  subtype     integer, as in the file
    wlan.sa                  ->  sa          lowercase address or missing
    wlan.da                  ->  da          lowercase address or missing
    wlan.bssid               ->  bssid       lowercase address or missing
    wlan.fixed.reason_code   ->  reason      integer or missing
    wlan.seq                 ->  seq         integer or missing
    wlan.fc.retry            ->  retry       0 / 1 or missing
    radiotap.dbm_antsignal   ->  rssi        first value; missing by default for CSV
    wlan.fc.protected        ->  protected   0 / 1 or missing
    wlan.rsn.capabilities.mfpc -> mfpc       0 / 1 or missing (see below)
    (see below)              ->  clock       time of day as text HH:MM:SS.mmm, card only

The mfpc field is the "Management Frame Protection Capable" bit from the RSN
element. Step 4 uses it to check whether the network supports PMF. The column
is optional: if it is not in the file, mfpc stays empty (and step 4 has
nothing to use).

The clock field is used only for the time of day on the card; all calculations
use ts. The time of day is copied directly from the text of the time column,
without any conversion:
    pcap   frame.time_utc   (tshark prints the UTC time as text)
    CSV    frame.time       (time stored in the dataset, dataset authors' time zone)
The column is optional - if it is missing, clock stays empty.

Running from the terminal:

    python export_rag_files.py "capture.pcap"
    python export_rag_files.py dataset_file.csv
    python export_rag_files.py file.csv --max-rows 0     # whole file
    python export_rag_files.py file.csv --csv-signal     # read rssi from CSV too
    python export_rag_files.py file.csv --show-raw       # raw cells without conversion
    python export_rag_files.py file.csv --show-signal    # preview of the signal column
    python export_rag_files.py "capture.pcap" --save-csv   # also save the CSV from tshark
"""

import argparse
import re
import subprocess
from pathlib import Path
import io

import pandas as pd

TSHARK_EXE = r"C:\Program Files\Wireshark\tshark.exe"

MAX_ROWS = 10

PCAP_TIME_COLUMN = "frame.time_epoch"
CSV_TIME_COLUMN = "frame.time_relative"

# Columns read from the source file (Wireshark field names).
# The first item is the time column for pcap; for CSV, source_columns replaces it.
SOURCE_COLUMNS = [
    "frame.time_epoch",
    "wlan.fc.type",
    "wlan.fc.subtype",
    "wlan.sa",
    "wlan.da",
    "wlan.bssid",
    "wlan.fixed.reason_code",
    "wlan.seq",
    "wlan.fc.retry",
    "radiotap.dbm_antsignal",
    "wlan.fc.protected",
]

# Columns with the time of day as text - only for the time on the card (clock field).
# Optional: if missing, the program does not stop; clock just stays empty.
PCAP_CLOCK_COLUMN = "frame.time_utc"
CSV_CLOCK_COLUMN = "frame.time"

# MFPC bit (Management Frame Protection Capable) from the RSN element.
# Filled only in frames that carry an RSN element (e.g. beacon, probe
# response, association request); in other frames the cell is empty.
# Optional: a missing column does not stop the program, mfpc stays empty.
RSN_MFPC_COLUMN = "wlan.rsn.capabilities.mfpc"

# Signal strength column. Required only when rssi is read
# (always for pcap; for CSV only with --csv-signal). A CSV without signal may lack it.
SIGNAL_COLUMN = "radiotap.dbm_antsignal"

def source_columns(time_column):
    """List of 11 columns with the given time column in first place."""
    return [time_column] + SOURCE_COLUMNS[1:]

SCHEMA_FIELDS = [
    "ts", "type", "subtype", "sa", "da", "bssid",
    "reason", "seq", "retry", "rssi", "protected", "mfpc", "clock",
]

MISSING_VALUES = {"", "?", "nan", "none", "null", "n/a", "na", "<na>"}

FLAG_VALUES = {"1": 1, "0": 0, "true": 1, "false": 0, "1.0": 1, "0.0": 0}



def run_tshark(pcap_path, max_rows=MAX_ROWS):
    """Runs tshark and returns its output (CSV) as text - without saving a file."""
    pcap_path = Path(pcap_path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f"No such pcap file: {pcap_path}")
    if not Path(TSHARK_EXE).is_file():
        raise FileNotFoundError(
            f"tshark not found at: {TSHARK_EXE}\n"
            "Fix the TSHARK_EXE constant at the top of the file."
        )
    command = [
        TSHARK_EXE,
        "-r", str(pcap_path),
        "-T", "fields",
        "-E", "header=y",       # first line = column names
        "-E", "separator=,",
        "-E", "quote=d",        # values in double quotes
        "-E", "occurrence=f",   # field occurring several times (antennas) - first only
    ]
    if max_rows:
        command += ["-c", str(max_rows)]
    for column in SOURCE_COLUMNS + [RSN_MFPC_COLUMN, PCAP_CLOCK_COLUMN]:
        command += ["-e", column]

    # capture_output=True: tshark output (stdout) and its messages (stderr) go to variables.
    completed = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        raise RuntimeError(f"Tshark failed:\n{completed.stderr}")
    return completed.stdout   # the whole CSV as a single text


def csv_source(source):
    """Source for pd.read_csv: a file path or in-memory text (StringIO).

    In-memory text is read like a file, starting where the previous read
    ended - that is why it is rewound to the beginning before every read.
    """
    if hasattr(source, "seek"):
        source.seek(0)
    return source

# def read_tshark_output(text):
#     """CSV od tsharka (tekst) -> tabela w schemacie."""
#     raw_table = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False)
#     return convert_to_schema(raw_table, use_signal=True, time_column=PCAP_TIME_COLUMN, clock_column=PCAP_CLOCK_COLUMN)
#
# def load_pcap(pcap_path, max_rows=MAX_ROWS):
#     return read_tshark_output(run_tshark(pcap_path, max_rows))
# def export_pcap_to_csv(pcap_path, csv_path=None, max_rows=MAX_ROWS):
#     """Uruchamia tshark, który zapisuje wybrane kolumny z pcap do pliku CSV.
#
#     Zwraca ścieżkę do utworzonego CSV (domyślnie obok pcap, ta sama nazwa).
#     """
#     pcap_path = Path(pcap_path)
#     if not pcap_path.is_file():
#         raise FileNotFoundError(f"Nie ma takiego pliku pcap: {pcap_path}")
#     if not Path(TSHARK_EXE).is_file():
#         raise FileNotFoundError(
#             f"Nie ma programu tshark pod ścieżką: {TSHARK_EXE}\n"
#             "Popraw stałą TSHARK_EXE na górze pliku."
#         )
#
#     if csv_path is None:
#         csv_path = pcap_path.with_suffix(".csv")
#
#     command = [
#         TSHARK_EXE,
#         "-r", str(pcap_path),
#         "-T", "fields",
#         "-E", "header=y",       # pierwsza linia = nazwy kolumn
#         "-E", "separator=,",
#         "-E", "quote=d",        # wartości w cudzysłowach
#         "-E", "occurrence=f",   # pole występujące kilka razy (anteny) - tylko pierwsze
#     ]
#     if max_rows:
#         command += ["-c", str(max_rows)]   # tylko pierwsze N pakietów
#     for column in SOURCE_COLUMNS + [RSN_MFPC_COLUMN, PCAP_CLOCK_COLUMN]:
#         command += ["-e", column]
#
#     with open(csv_path, "w", newline="") as output_file:
#         subprocess.run(command, stdout=output_file, check=True)
#     return Path(csv_path)



# Step 2a: converting a single cell (text from the file -> value in the schema)
def clean_text(value):
    """Strips spaces; turns entries like '', '?', 'nan' into missing (None)."""
    if value is None:
        return None
    value = str(value).strip()
    if value.lower() in MISSING_VALUES:
        return None
    return value


def first_part(value):
    """If a cell holds several values at once, keeps only the first one.

    In the dataset CSV, values are sometimes joined with a hyphen or a comma:
    'aa:bb:cc:dd:ee:01-aa:bb:cc:dd:ee:01' -> 'aa:bb:cc:dd:ee:01', '12-12' -> '12'.
    A minus at the very beginning ('-45') is the number's sign, so it stays.
    """
    return re.split(r"(?<=.)[-,]", value)[0].strip()


def to_int(value):
    """Text -> integer. Missing or unreadable -> None.

    Handles three notations: '12', '12.0' and hexadecimal '0x0007'
    (this is how tshark writes the reason code).
    """
    value = clean_text(value)
    if value is None:
        return None
    value = first_part(value)
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(float(value))
    except ValueError:
        return None


def to_flag(value):
    """'1' / '0' / 'True' / 'False' -> 1 / 0. Brak -> None."""
    value = clean_text(value)
    if value is None:
        return None
    return FLAG_VALUES.get(first_part(value).lower())


def to_mfpc(value):
    """MFPC bit: '1' / '0' / 'True' / 'False' -> 1 / 0. Missing -> None.

    Unlike to_flag, the cell is read as a whole, without first_part:
    values in this column are not joined, so there is nothing to split.
    """
    value = clean_text(value)
    if value is None:
        return None
    return FLAG_VALUES.get(value.lower())


def to_mac_address(value):
    """'AA:BB:CC:DD:EE:01' -> 'aa:bb:cc:dd:ee:01'. Missing -> None."""
    value = clean_text(value)
    if value is None:
        return None
    return first_part(value).lower()


def first_signal_value(value):
    """First number in the cell: '-45,-45' -> -45, '-34-37-34' -> -34."""
    value = clean_text(value)
    if value is None:
        return None
    match = re.match(r"-?\d+", value)
    if match is None:
        return None
    return int(match.group())


def clock_text(time_text):
    """Time of day copied directly from the time column text, truncated to milliseconds.

    'Dec 18- 2020 17:49:54.921281000 GTB Standard Time' -> '17:49:54.921'
    'Dec 29, 2025 09:20:01.500000000 UTC'               -> '09:20:01.500'
    Nothing is converted: neither the time zone nor rounding - the time is only
    cut out of the text. No time in the text or an empty cell -> None.
    """
    time_text = clean_text(time_text)
    if time_text is None:
        return None
    match = re.search(r"(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?", time_text)
    if match is None:
        return None
    hours, minutes, secs, fraction = match.groups()
    milliseconds = ((fraction or "") + "000")[:3]     # ucięcie do 3 cyfr
    return f"{int(hours):02d}:{minutes}:{secs}.{milliseconds}"


def optional_column(raw_table, column, convert):
    """A column that may be missing from the file.

    In the file  -> every cell goes through convert.
    Not in it    -> a column of missing values (None), as many rows as the table.
    """
    if column in raw_table.columns:
        return raw_table[column].map(convert)
    return pd.Series([None] * len(raw_table), index=raw_table.index, dtype=object)


def to_int_column(values):
    """An integer column that may contain missing values."""
    return pd.array(list(values), dtype="Int64")


# Krok 2b: converting the whole table
def check_columns_exist(csv_path, required_columns):
    """Stops the program if any column is missing from the file.

    Without this, a wrong column name would give empty results that look like 'no attack'.
    """
    file_columns = list(pd.read_csv(csv_source(csv_path), nrows=0).columns)
    missing = [column for column in required_columns if column not in file_columns]
    if missing:
        name = "tshark output" if hasattr(csv_path, "seek") else csv_path
        raise ValueError(
            f"{name}: missing columns {missing}\n"
            f"Columns in the file: {file_columns}"
        )
    return file_columns


def convert_to_schema(raw_table, use_signal=True, time_column=PCAP_TIME_COLUMN,
                      clock_column=PCAP_CLOCK_COLUMN):
    """Table with text columns from the file -> table with schema fields.

    time_column    which file column to take the ts time from (for calculations)
    clock_column   which file column to copy the clock time from (card only)
    """
    if use_signal:
        signal = raw_table["radiotap.dbm_antsignal"].map(first_signal_value)
    else:
        signal = [None] * len(raw_table)

    ts = pd.to_numeric(raw_table[time_column], errors="coerce")
    clock = optional_column(raw_table, clock_column, clock_text)     # time of the day straight from text
    mfpc = optional_column(raw_table, RSN_MFPC_COLUMN, to_mfpc)       # MFPC bit from RSN

    return pd.DataFrame({
        "ts":        ts,
        "type":      to_int_column(raw_table["wlan.fc.type"].map(to_int)),
        "subtype":   to_int_column(raw_table["wlan.fc.subtype"].map(to_int)),
        "sa":        raw_table["wlan.sa"].map(to_mac_address),
        "da":        raw_table["wlan.da"].map(to_mac_address),
        "bssid":     raw_table["wlan.bssid"].map(to_mac_address),
        "reason":    to_int_column(raw_table["wlan.fixed.reason_code"].map(to_int)),
        "seq":       to_int_column(raw_table["wlan.seq"].map(to_int)),
        "retry":     to_int_column(raw_table["wlan.fc.retry"].map(to_flag)),
        "rssi":      to_int_column(signal),
        "protected": to_int_column(raw_table["wlan.fc.protected"].map(to_flag)),
        "mfpc":      to_int_column(mfpc),
        "clock":     clock,
    })


# Main functions
def load_csv(csv_path, use_signal=False, max_rows=MAX_ROWS, chunk_size=200_000,
             time_column=CSV_TIME_COLUMN, clock_column=CSV_CLOCK_COLUMN):
    """Loads a CSV file and returns a table in the schema.

    Only 11 columns are read (the time column and 10 fields from SOURCE_COLUMNS)
    plus - if present in the file - the time-of-day column (clock_column) and
    the MFPC bit column (RSN_MFPC_COLUMN). The signal column (SIGNAL_COLUMN) is
    required only with use_signal=True - without it rssi stays empty anyway.

    use_signal    False = the rssi field stays empty (default, because in the
                  dataset CSV the signal column holds a sum of antennas, not the first value)
    max_rows      how many first packets to load; None = whole file
    chunk_size    the file is read in chunks of this many rows
    time_column   time column; for the dataset CSV frame.time_relative
    clock_column  column with time of day as text; for the dataset CSV frame.time
    """
    columns = source_columns(time_column)
    if not use_signal:
        # rssi is not read, so the signal column is not needed
        columns = [column for column in columns if column != SIGNAL_COLUMN]
    file_columns = check_columns_exist(csv_path, columns)

    # Optional columns: added only if they are present in the file.
    for optional in [RSN_MFPC_COLUMN, clock_column]:
        if optional in file_columns and optional not in columns:
            columns = columns + [optional]
    if RSN_MFPC_COLUMN not in file_columns:
        print(f"Warning: no {RSN_MFPC_COLUMN} column in the file - the mfpc field stays empty")

    reader = pd.read_csv(
        csv_source(csv_path),
        usecols=columns,  # only these columns, not all 254
        dtype=str,  # everything as text - we do the conversion ourselves
        keep_default_na=False,  # pandas should not guess what counts as missing
        nrows=max_rows,
        chunksize=chunk_size,
    )
    parts = [convert_to_schema(raw_chunk, use_signal, time_column, clock_column)
             for raw_chunk in reader]
    return pd.concat(parts, ignore_index=True)


def read_tshark_output(text, max_rows=MAX_ROWS):
    """CSV from tshark (in-memory text) -> table in the schema.

    The same path as for a CSV file (load_csv), only the source is text:
    io.StringIO pretends to be a file, but lives entirely in memory. Settings
    for pcap: signal is read, time from frame.time_epoch, clock from frame.time_utc.
    """
    return load_csv(io.StringIO(text), use_signal=True, max_rows=max_rows,
                    time_column=PCAP_TIME_COLUMN, clock_column=PCAP_CLOCK_COLUMN)

def load_pcap(pcap_path, max_rows=MAX_ROWS):
    """Loads a pcap file and returns a table in the schema - without saving a CSV file.

    tshark -> CSV text in memory -> read_tshark_output -> table.
    """
    return read_tshark_output(run_tshark(pcap_path, max_rows=max_rows), max_rows=max_rows)

# --- Checking the result ---
def show_raw_signal_values(csv_path, max_rows=200_000, how_many=15):
    """Shows what the signal column looks like in the file - without any conversion."""
    column = "radiotap.dbm_antsignal"
    check_columns_exist(csv_path, [column])
    values = pd.read_csv(
        csv_source(csv_path), usecols=[column], dtype=str,
        keep_default_na=False, nrows=max_rows,
    )[column]

    print(f"{column}: {len(values)} rows, most frequent values:")
    for value, count in values.value_counts().head(how_many).items():
        print(f"  {value!r:<22}{count}")

    several = values.str.fullmatch(r"\s*-?\d+(\s*[,;|]?\s*-\d+)+\s*").sum()
    very_low = (pd.to_numeric(values, errors="coerce") < -110).sum()
    print(f"cells with several values at once: {several}")
    print(f"single numbers below -110 dBm (suspected sum): {very_low}")


def show_raw_values(csv_path, max_rows=MAX_ROWS, time_column=CSV_TIME_COLUMN):
    """Prints cells exactly as they are stored in the file (each in quotes)."""
    columns = [column for column in source_columns(time_column) if column != SIGNAL_COLUMN]
    file_columns = check_columns_exist(csv_path, columns)
    for optional in [SIGNAL_COLUMN, RSN_MFPC_COLUMN]:
        if optional in file_columns:
            columns = columns + [optional]
    raw_table = pd.read_csv(csv_source(csv_path), usecols=columns, dtype=str, keep_default_na=False, nrows=max_rows)
    for row_number, row in raw_table.iterrows():
        print(f"row {row_number}:")
        for column in columns:
            print(f"  {column:<28}{row[column]!r}")


def print_summary(table):
    """Prints the number of loaded packets and the number of missing values in each field."""
    print(f"Frames loaded: {len(table)}")
    print("Missing values per field:")
    for field in SCHEMA_FIELDS:
        print(f"  {field:<10}{table[field].isna().sum()}")


def table_as_text(table, max_rows=20):
    """Turns the table into printable text; missing values are blank.

    Only the look of the printout changes - in the table itself missing values
    stay missing, and rows are still numbered from 0. The printout numbers from 1.
    """
    display = table.astype(object)                      # copy in which a cell can be text
    display["ts"] = table["ts"].map("{:.6f}".format)    # time with 6 decimal places
    display = display.where(table.notna(), "")          # where missing - empty text
    display.index = display.index + 1                   # numbering from 1 in the printout only
    return display.to_string(max_rows=max_rows)


def main():
    parser = argparse.ArgumentParser(
        description="Load a pcap or CSV file into the common schema.")
    parser.add_argument("file", help=".pcap / .pcapng / .cap or .csv file")
    parser.add_argument(
        "--max-rows", type=int, default=MAX_ROWS,
        help=f"how many first frames to load (default {MAX_ROWS}; 0 = whole file)")
    parser.add_argument(
        "--csv-signal", action="store_true",
        help="read signal strength from CSV too (by default rssi from CSV stays empty)")
    parser.add_argument(
        "--show-raw", action="store_true",
        help="only show raw cells from the file, without conversion, and exit")
    parser.add_argument(
        "--show-signal", action="store_true",
        help="only show the raw signal column and exit")
    parser.add_argument(
        "--save-csv", action="store_true",
        help="pcap only: also save tshark output as a .csv file next to the pcap")
    args = parser.parse_args()

    path = Path(args.file)
    max_rows = args.max_rows or None
    is_pcap = path.suffix.lower() in {".pcap", ".pcapng", ".cap"}

    # pcap: tshark runs once, its output (CSV text) is kept in memory
    if is_pcap:
        tshark_text = run_tshark(path, max_rows=max_rows)
        if args.save_csv:
            csv_path = path.with_suffix(".csv")
            csv_path.write_text(tshark_text, encoding="utf-8")
            print(f"saved: {csv_path}")
        source = io.StringIO(tshark_text)
    else:
        source = path

    if args.show_raw:
        time_column = PCAP_TIME_COLUMN if is_pcap else CSV_TIME_COLUMN
        show_raw_values(source, max_rows=max_rows, time_column=time_column)
        return

    if args.show_signal:
        show_raw_signal_values(source)
        return

    if is_pcap:
        table = read_tshark_output(tshark_text, max_rows=max_rows)
    else:
        table = load_csv(path, use_signal=args.csv_signal, max_rows=max_rows)

    print_summary(table)
    print(table_as_text(table))


if __name__ == "__main__":
    main()