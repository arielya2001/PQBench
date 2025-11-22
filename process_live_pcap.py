#!/usr/bin/env python3

from nfstream import NFStreamer
import TDL
import os
import pandas as pd
import sys
import logging
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def process_single_pcap(pcap_path: str, num_of_packets: int) -> list | None:
    """
    Processes a single pcap file and returns its TDL_ip_TDL data
    using NFStreamer v6.5.3 + TDL plugin.
    """
    try:
        streamer = NFStreamer(
            source=pcap_path,
            udps=TDL.TDL(),
        )

        all_streams_data = []

        for flow in streamer:
            # בודקים את הפלגין תחת flow.udps
            if hasattr(flow.udps, "ip_TDL"):
                all_streams_data.append(flow.udps.ip_TDL)

        if not all_streams_data or not all_streams_data[-1]:
            logging.warning(f"No TDL data found in {pcap_path}")
            return None

        result = all_streams_data[-1]

        result = [str(item) for item in result]

        return result[:num_of_packets]

    except Exception as e:
        logging.error(f"Failed to process {pcap_path}: {e}")
        return None


def main() -> None:
    if len(sys.argv) < 2:
        logging.error("Usage: python process_live_pcap.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]

    if not os.path.exists(pcap_path):
        logging.error(f"Error: Pcap file not found at {pcap_path}")
        sys.exit(1)

    num_of_packets = 20
    output_filename = 'live_data_for_classification_122.csv'

    logging.info(f"Processing live file: {pcap_path}")

    tdl_data = process_single_pcap(pcap_path, num_of_packets)

    if tdl_data:
        df = pd.DataFrame([tdl_data])
        df.to_csv(output_filename, index=False, header=False)
        logging.info(f"Successfully created: {output_filename} with 1 row.")
    else:
        logging.error(f"Failed to extract TDL data from {pcap_path}.")


if __name__ == "__main__":
    # auto-copy fallback
    if not os.path.exists('TDL.py'):
        logging.info("TDL.py not found in current dir, trying to copy from TDL/TDL.py")
        try:
            shutil.copyfile('TDL/TDL.py', 'TDL.py')
            logging.info("Successfully copied TDL.py")
        except Exception as e:
            logging.error(f"Error: TDL.py not found and failed to copy: {e}")
            sys.exit(1)

    main()
