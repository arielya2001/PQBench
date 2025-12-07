#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pandas as pd
import sys
import logging
from scapy.all import rdpcap, TCP, IP  # יבוא נדרש לניתוח pcap
import shutil  # נחוץ כדי להעתיק קבצים

# הגדרות לוגינג
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# קבועים לזיהוי TLS
TLS_HANDSHAKE = 22
CLIENT_HELLO = 1
SERVER_HELLO = 2

def get_label_from_folder(name: str) -> int:
    # OS
    if name.startswith("linux"):
        os_code = 1
    elif name.startswith("windows"):
        os_code = 2
    elif name.startswith("macos"):
        os_code = 3
    else:
        return 999  # תיקייה לא תקינה

    # Browser
    if "_firefox_" in name:
        browser_code = 1
    elif "_chrome_" in name:
        browser_code = 2
    else:
        return 999

    # Algo
    if name.endswith("kyber"):
        algo_code = 1
    elif name.endswith("mlkem"):
        algo_code = 2
    elif name.endswith("nonpqc") or name.endswith("nopqc"):
        algo_code = 0
    else:
        return 999

    return os_code * 100 + browser_code * 10 + algo_code



def extract_tls_features(pcap_path: str):
    try:
        pcap = rdpcap(pcap_path)
    except Exception as e:
        logging.error(f"Error reading pcap file {pcap_path}: {e}")
        return 0, 0

    ch_size = 0
    sh_size = 0

    client_ip = None
    server_ip = None
    server_port = None

    def is_tls_handshake(payload):
        return len(payload) > 5 and payload[0] == 22

    def handshake_type(payload):
        if len(payload) < 6:
            return None
        return payload[5]

    # new: extract handshake length (true total length)
    def handshake_total_length(payload):
        if len(payload) < 9:
            return None
        return (payload[6] << 16) | (payload[7] << 8) | payload[8]

    for pkt in pcap:
        if not pkt.haslayer(TCP) or not pkt.haslayer("Raw"):
            continue

        payload = bytes(pkt["Raw"].load)

        # -----------------------
        # Detect Client Hello
        # -----------------------
        if not ch_size and is_tls_handshake(payload) and handshake_type(payload) == 1:
            ch_len = handshake_total_length(payload)
            if ch_len:
                ch_size = ch_len

            client_ip = pkt[IP].src
            server_ip = pkt[IP].dst
            server_port = pkt[TCP].dport
            continue

        # -----------------------
        # Detect Server Hello
        # -----------------------
        if ch_size and not sh_size:

            if pkt[IP].src != server_ip:
                continue

            if not is_tls_handshake(payload):
                continue

            if handshake_type(payload) != 2:
                continue

            sh_len = handshake_total_length(payload)
            if sh_len:
                sh_size = sh_len
                break

    return ch_size, sh_size




def scan_and_extract(root_data_dir: str) -> None:
    """
    סורק את מבנה התיקיות החדש ('output'), מחלץ את גדלי ה-Hello
    ויוצר קובץ CSV עם התוצאות.
    """
    logging.info(f"\n--- Starting TLS Hello Feature Extraction ---")

    all_results = []

    try:
        # Level 1: Loop through the classification folders (e.g., 'linux_chrome_kyber')
        for label_dir_name in os.listdir(root_data_dir):
            label_path = os.path.join(root_data_dir, label_dir_name)

            # מדלגים על קבצים או תיקיות שלא קשורות (מצפים למבנה כמו 'X_Y_Z')
            if not os.path.isdir(label_path) or not label_dir_name.count('_') == 2:
                continue

            final_label = get_label_from_folder(label_dir_name)
            logging.info(f"Scanning label folder: {label_dir_name} (Label: {final_label})")

            # Level 2: לולאה בתוך תיקיית ה-session (session-2025-11-08_14-06-09)
            for session_dir_name in os.listdir(label_path):
                session_path = os.path.join(label_path, session_dir_name)

                if not os.path.isdir(session_path) or not session_dir_name.startswith("session-"):
                    continue

                # Level 3: סריקת קבצי הסשן בתוך התיקייה
                for file in os.listdir(session_path):

                    # מחפשים קבצים שמתחילים ב-"session" (100 קבצי הסשן)
                    if file.startswith('session-') and file.endswith('.pcap'):
                        full_pcap_path = os.path.join(session_path, file)

                        # חילוץ הפיצ'רים המדויקים
                        ch_size, sh_size = extract_tls_features(full_pcap_path)

                        # הוספת התוצאה לטבלה
                        all_results.append({
                            "session_path": os.path.join(label_dir_name, session_dir_name, file),
                            "label": final_label,
                            "CH_Size": ch_size,
                            "SH_Size": sh_size
                        })

                logging.info(f"  -> Processed sessions in {session_dir_name}")


    except FileNotFoundError:
        logging.error(f"Error: Directory '{root_data_dir}' not found. Make sure it's correct.")
        return

    # 4. יצירת ושמירת ה-DataFrame הסופי
    if not all_results:
        logging.warning("No data processed. Exiting.")
        return

    df = pd.DataFrame(all_results)
    output_filename = 'tls_hello_sizes_report.csv'

    df.to_csv(output_filename, index=False)
    logging.info(f"Successfully created: {output_filename} with {len(df)} total rows.")


if __name__ == "__main__":
    try:
        import pandas
        import scapy.all
    except ImportError as e:
        logging.error(f"Missing required library: {e}. Please install requirements.txt first.")
        sys.exit(1)

    scan_and_extract(root_data_dir='output')


