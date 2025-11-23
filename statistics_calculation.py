import pandas as pd
import ast
import numpy as np

# ====== 1. קריאת הקובץ ======
df = pd.read_csv("all-files-with-100-pcaps-with-20-packets.csv")

# הפיכת מחרוזות כמו "[1, 52, 0]" לרשימות אמיתיות
packet_cols = [str(i) for i in range(20)]
for col in packet_cols:
    df[col] = df[col].apply(lambda x: ast.literal_eval(x))

results = []

# ====== 2. חישוב סטטיסטיקות לכל לייבל ======
for label, group in df.groupby("label"):

    all_sizes = []
    all_IATs = []
    CH_sizes = []
    SH_sizes = []

    for _, row in group.iterrows():

        # גודל פקטות
        session_sizes = [pkt[1] for pkt in row[packet_cols]]
        all_sizes.extend(session_sizes)

        # IATs
        times = [pkt[2] for pkt in row[packet_cols]]
        iats = np.diff(times)
        all_IATs.extend(iats)

        # Client Hello = packet index 3
        CH_sizes.append(row["3"][1])

        # Server Hello = packet index 5
        SH_sizes.append(row["5"][1])

    # ====== 3. בניית שורת תוצאות ======
    results.append({
        "label": label,
        "mean_pkt_size": np.mean(all_sizes),
        "std_pkt_size": np.std(all_sizes),
        "mean_IAT": np.mean(all_IATs),
        "std_IAT": np.std(all_IATs),
        "mean_CH": np.mean(CH_sizes),
        "std_CH": np.std(CH_sizes),
        "mean_SH": np.mean(SH_sizes),
        "std_SH": np.std(SH_sizes),
    })

# ====== 4. ייצוא לקובץ =====
out_df = pd.DataFrame(results)
out_df = out_df.sort_values("label")

out_df.to_csv("class_level_statistics.csv", index=False)

print("✔ הייצוא הושלם → class_level_statistics.csv")
print(out_df)
