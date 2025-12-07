import pandas as pd
import ast
import numpy as np
import os


DATASET_PATH = os.path.join(
    os.getcwd(),
    "dataset-100-pcaps-20-packets.csv"
)

print("Loading:", DATASET_PATH)
df = pd.read_csv(DATASET_PATH)

packet_cols = [str(i) for i in range(20)]

# Convert "[1, 52, 0]" → [1, 52, 0]
for col in packet_cols:
    df[col] = df[col].apply(lambda x: ast.literal_eval(x))

results = []

for label, group in df.groupby("label"):

    all_sizes = []
    all_IATs = []
    all_mean_relative_times = []
    all_durations = []

    for _, row in group.iterrows():

        packets = [row[c] for c in packet_cols]

        # Sizes
        sizes = [p[1] for p in packets]
        all_sizes.extend(sizes)

        # IAT
        times = [p[2] for p in packets]
        iats = np.diff(times)
        all_IATs.extend(iats)

        # Relative time (mean timestamps in this PCAP)
        mean_rel_time = np.mean(times)
        all_mean_relative_times.append(mean_rel_time)

        # Duration (timestamp of last packet)
        duration = times[-1]
        all_durations.append(duration)

    # Stats for the class
    results.append({
        "label": int(label),
        "mean_pkt_size": np.mean(all_sizes),
        "std_pkt_size": np.std(all_sizes),
        "mean_IAT": np.mean(all_IATs),
        "std_IAT": np.std(all_IATs),
        "mean_relative_time": np.mean(all_mean_relative_times),
        "mean_duration": np.mean(all_durations),
    })

# Create output DataFrame
out_df = pd.DataFrame(results).sort_values("label")
OUTPUT_PATH = "class_level_statistics_new.csv"

out_df.to_csv(OUTPUT_PATH, index=False)

print("✔ הייצוא הושלם →", OUTPUT_PATH)
print(out_df)
