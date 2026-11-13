import subprocess
import csv
import io
import os
from collections import Counter


def generate_summary_from_pcap(pcap_path, tshark_path):
    if not os.path.exists(pcap_path):
        return f"ERROR: pcap file not found: {pcap_path}"
    if not os.path.exists(tshark_path):
        return f"ERROR: tshark executable not found: {tshark_path}"

    print(f"Analyzing file: {pcap_path} ...\n")

    command = [
        tshark_path,
        "-r", pcap_path,
        "-Y", "wlan",
        "-T", "fields",
        "-e", "frame.time_relative",
        "-e", "wlan.fc.type",
        "-e", "wlan.fc.subtype",
        "-e", "wlan.fc.protected",
        "-e", "wlan.sa",
        "-e", "wlan.da",
        "-e", "wlan.bssid",
        "-e", "wlan.fixed.reason_code",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "occurrence=f"
    ]

    try:
        proces = subprocess.run(command, capture_output=True, text=True, check=True)
        csv_data = proces.stdout
    except subprocess.CalledProcessError as e:
        return f"Tshark error: {e.stderr}"

    packet_count = 0
    total_mgmt_count = 0
    unprotected_mgmt_count = 0
    protected_mgmt_count = 0
    unrecognized_protected_values = Counter()

    min_time = float('inf')
    max_time = 0.0

    management_subtypes = set()
    reason_codes = set()

    sa_counter = Counter()
    da_counter = Counter()
    bssid_counter = Counter()

    unprotected_sa_counter = Counter()
    protected_sa_counter = Counter()

    reader = csv.DictReader(io.StringIO(csv_data))

    for row in reader:
        packet_count += 1

        try:
            t = float(row['frame.time_relative'])
            if t < min_time: min_time = t
            if t > max_time: max_time = t
        except ValueError:
            pass

        sa = row.get('wlan.sa', '')
        if sa:
            sa_counter[sa.lower()] += 1

        da = row.get('wlan.da', '')
        if da:
            da_counter[da.lower()] += 1

        bssid = row.get('wlan.bssid', '')
        if bssid:
            bssid_counter[bssid.lower()] += 1

        fc_type = row.get('wlan.fc.type', '')
        if fc_type == '0':
            total_mgmt_count += 1

            subtype = row.get('wlan.fc.subtype', '')
            if subtype:
                management_subtypes.add(subtype)

            rc = row.get('wlan.fixed.reason_code', '')
            if rc:
                reason_codes.add(rc)

            # FIX: value normalization + explicit fallback,
            # so that EVERY mgmt frame ends up as either protected OR unprotected
            protected_raw = (row.get('wlan.fc.protected', '') or '').strip().lower()

            if protected_raw in ('1', 'true', '0x1'):
                protected_mgmt_count += 1
                if sa:
                    protected_sa_counter[sa.lower()] += 1
            else:
                # '', '0', 'false', '0x0' and anything else = protection bit not set -> unprotected
                unprotected_mgmt_count += 1
                if sa:
                    unprotected_sa_counter[sa.lower()] += 1

                if protected_raw not in ('0', 'false', '0x0'):
                    unrecognized_protected_values[protected_raw or '<empty>'] += 1

    duration = round(max_time - min_time, 4) if packet_count > 0 else 0

    unprotected_ratio = 0.0
    if total_mgmt_count > 0:
        unprotected_ratio = round(unprotected_mgmt_count / total_mgmt_count, 2)

    subtypes_list = [int(x) for x in management_subtypes if x.isdigit()]
    reasons_list = [int(x) for x in reason_codes if x.isdigit()]

    summary = "Network flow summary:\n"
    summary += f"duration={duration}\n"
    summary += f"packet_count={packet_count}\n"
    summary += f"mgmt_packet_count={total_mgmt_count}\n"

    summary += f"unprotected_mgmt_count={unprotected_mgmt_count}\n"
    summary += f"protected_mgmt_count={protected_mgmt_count}\n"
    summary += f"unprotected_mgmt_ratio={unprotected_ratio}\n"

    assert unprotected_mgmt_count + protected_mgmt_count == total_mgmt_count

    summary += f"mgmt_subtypes={sorted(subtypes_list)}\n"

    if reasons_list:
        summary += f"reason_codes={sorted(reasons_list)}\n"

    summary += f"source_addresses={dict(sa_counter)}\n"
    summary += f"destination_addresses={dict(da_counter)}\n"
    summary += f"bssid_address={dict(bssid_counter)}\n"

    summary += f"unprotected_source_addresses={dict(unprotected_sa_counter)}\n"
    summary += f"protected_source_addresses={dict(protected_sa_counter)}\n"

    if unrecognized_protected_values:
        summary += f"[debug] unusual wlan.fc.protected values: {dict(unrecognized_protected_values)}\n"

    return summary


tshark_exe = r"C:\Program Files\Wireshark\tshark.exe"
pcap_file= r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\pcap\Deauthentication\pcapy to 10 packets\1088022-1088027(6 packets).pcap"
#pcap_file = r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\pcap\Deauthentication\pcapy to 10 packets\1100010-1100019(10 packets).pcap"
#pcap_file = r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\pcap\Deauthentication\pcapy to 10 packets\1200075-1200084(10 packets).pcap"
#pcap_file = r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\pcap\Deauthentication\pcaps to 100 packets\1176999-1177098(100 packets).pcap"
#pcap_file = r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\pcap\Deauthentication\pcaps to 1000 packets\1260999-1261998(1000 packets).pcap"

summary_text = generate_summary_from_pcap(pcap_file, tshark_exe)
print(summary_text)