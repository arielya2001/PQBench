import pandas as pd
import ast
import numpy as np

# --- Load your dataset ---
df = pd.read_csv("/mnt/c/Users/User/PycharmProjects/PQBench/dataset-100-pcaps-20-packets.csv")

# Convert "[1, 52, 0]" → [1, 52, 0]
def parse(cell):
    try:
        return ast.literal_eval(cell)
    except:
        return None

for i in range(20):
    df[str(i)] = df[str(i)].apply(parse)

rows = []

# For each label
for label, group in df.groupby("label"):

    # For packet index 0..19
    for p in range(20):

        sizes = []

        # Gather size of packet p from every session
        for _, row in group.iterrows():
            pkt = row[str(p)]
            if pkt is None:
                continue
            size = pkt[1]   # second element is size
            sizes.append(size)

        # Compute statistics
        mean_size = np.mean(sizes)
        std_size = np.std(sizes)

        rows.append({
            "label": label,
            "packet_index": p,
            "mean_size": mean_size,
            "std_size": std_size
        })

# Export
out_path = "/mnt/c/Users/User/PycharmProjects/PQBench/stats_per_index.csv"
pd.DataFrame(rows).to_csv(out_path, index=False)

print("✔ created:", out_path)
