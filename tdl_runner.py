#!/usr/bin/env python3

from nfstream import NFStreamer
import TDL
import os
import pandas as pd
import sys
import logging
import shutil

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")


# ---------------------------------
# LABEL mapping (folder → numeric)
# ---------------------------------
LABEL_MAP = {
    "linux_firefox_nonpqc": 110,
    "linux_firefox_kyber": 111,
    "linux_firefox_mlkem": 112,
    "linux_chrome_nonpqc": 120,
    "linux_chrome_kyber": 121,
    "linux_chrome_mlkem": 122,
    "windows_firefox_nonpqc": 210,
    "windows_firefox_kyber": 211,
    "windows_firefox_mlkem": 212,
    "windows_chrome_nonpqc": 220,
    "windows_chrome_kyber": 221,
    "windows_chrome_mlkem": 222,
    "macos_firefox_nonpqc": 310,
    "macos_firefox_kyber": 311,
    "macos_firefox_mlkem": 312,
    "macos_chrome_nonpqc": 320,
    "macos_chrome_kyber": 321,
    "macos_chrome_mlkem": 322,
}


def process_single_pcap(pcap_path: str, num_of_packets: int) -> list | None:
    """
    Extracts TDL.ip_TDL using NFStreamer 6.5.x + TDL plugin
    """
    try:
        streamer = NFStreamer(
            source=pcap_path,
            udps=TDL.TDL(),
        )

        all_streams_data = []

        for flow in streamer:
            if hasattr(flow.udps, "ip_TDL"):
                all_streams_data.append(flow.udps.ip_TDL)

        if not all_streams_data or not all_streams_data[-1]:
            logging.warning(f"No TDL data found in {pcap_path}")
            return None

        result = [str(item) for item in all_streams_data[-1]]
        return result[:num_of_packets]

    except Exception as e:
        logging.error(f"Failed to process {pcap_path}: {e}")
        return None



def process_dataset(root_output_dir: str, num_of_pcaps_per_label: int, num_of_packets: int):
    logging.info(f"\n--- Processing DATASET ({num_of_packets} packets) ---")

    all_rows = []

    # iterate over label directories (linux_chrome_kyber, windows_firefox_mlkem,...)
    for label in os.listdir(root_output_dir):
        label_path = os.path.join(root_output_dir, label)

        if not os.path.isdir(label_path):
            continue

        logging.info(f"\n Label: {label}")

        # convert label folder → numeric label
        numeric_label = LABEL_MAP.get(label)
        if numeric_label is None:
            logging.warning(f"Unknown label folder '{label}', skipping.")
            continue

        # iterate over ALL session folders inside this label
        session_dirs = [
            d for d in os.listdir(label_path)
            if os.path.isdir(os.path.join(label_path, d))
        ]

        if not session_dirs:
            logging.warning(f"No sessions inside {label}")
            continue

        for session_folder in session_dirs:
            session_path = os.path.join(label_path, session_folder)

            logging.info(f"  ▶ Session: {session_folder}")

            files = os.listdir(session_path)
            # find all .pcap files EXCEPT raw capture files
            pcap_files = [
                f for f in files
                if f.endswith(".pcap")
                   and not "raw" in f.lower()
                   and not "debug" in f.lower()
                   and not f.startswith("_")
            ]

            pcap_files.sort()

            if not pcap_files:
                logging.warning(f"  No pcap files in session {session_folder}")
                continue

            # limit number of pcaps per label (across sessions)
            pcap_files = pcap_files[:num_of_pcaps_per_label]

            for pcap in pcap_files:
                full_path = os.path.join(session_path, pcap)

                tdl_data = process_single_pcap(full_path, num_of_packets)

                if tdl_data:
                    # append numeric label as last column
                    tdl_data.append(numeric_label)
                    all_rows.append(tdl_data)

    if not all_rows:
        logging.warning("No rows processed!")
        return

    df = pd.DataFrame(all_rows)
    df.rename(columns={df.columns[-1]: "label"}, inplace=True)

    outname = f"dataset-{num_of_pcaps_per_label}-pcaps-{num_of_packets}-packets.csv"
    df.to_csv(outname, index=False)

    logging.info(f"\n Created CSV: {outname} ({len(df)} rows)")



def main():
    root_output_dir = "output"   # new structure
    num_of_pcaps_per_label = 100

    # generate 5 datasets: 1,5,10,15,20 packets
    for packets in [1, 5, 10, 15, 20]:
        process_dataset(root_output_dir, num_of_pcaps_per_label, packets)


if __name__ == "__main__":
    # auto-copy fallback for TDL
    if not os.path.exists("TDL.py"):
        logging.info("TDL.py not found, copying...")
        try:
            shutil.copyfile("TDL/TDL.py", "TDL.py")
            logging.info("Copied TDL.py")
        except Exception as e:
            logging.error(f"Failed to copy TDL.py: {e}")
            sys.exit(1)

    main()
