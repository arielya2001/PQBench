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


def extract_label_from_filename(filename: str) -> int | None:
    """
    session-210-2025-11-08_14-06-09-00 → label=210
    """
    try:
        parts = filename.split("-")
        return int(parts[1])
    except:
        return None


def process_dataset(root_output_dir: str, num_of_pcaps_per_label: int, num_of_packets: int):
    logging.info(f"\n--- Processing DATASET ({num_of_packets} packets) ---")

    all_rows = []

    # traverse all categories (linux_chrome_kyber, windows_firefox_mlkem, ...)
    for method_dir in os.listdir(root_output_dir):
        method_path = os.path.join(root_output_dir, method_dir)

        if not os.path.isdir(method_path):
            continue

        logging.info(f"\n Method: {method_dir}")

        # inside each: exactly ONE session folder
        session_dirs = [
            d for d in os.listdir(method_path)
            if os.path.isdir(os.path.join(method_path, d))
        ]

        if not session_dirs:
            logging.warning(f"No session folder in {method_dir}")
            continue

        session_folder = session_dirs[0]
        session_path = os.path.join(method_path, session_folder)

        logging.info(f"  ▶ Session: {session_folder}")

        files = os.listdir(session_path)

        # collect pcap files
        pcap_files = [
            f for f in files
            if f.startswith("session-") and f.endswith(".pcap")
        ]
        pcap_files.sort()

        if not pcap_files:
            logging.warning(f"  No pcap files inside {session_folder}")
            continue

        # cap to 100 per category
        pcap_files = pcap_files[:num_of_pcaps_per_label]

        for pcap in pcap_files:
            full_path = os.path.join(session_path, pcap)

            label = extract_label_from_filename(pcap)
            if label is None:
                logging.warning(f"Could not parse label for {pcap}")
                continue

            tdl_data = process_single_pcap(full_path, num_of_packets)

            if tdl_data:
                tdl_data.append(label)
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
    root_output_dir = "output"   #new structure
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
