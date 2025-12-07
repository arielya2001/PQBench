import pandas as pd
import numpy as np

df = pd.read_csv("tls_hello_sizes_report.csv")

# נמחק שורות שאין בהן נתונים (אם מופיע 0 או ריק)
df = df.replace("", np.nan)
df = df.dropna(subset=["CH_Size", "SH_Size"])

# לוודא שמספרים
df["CH_Size"] = df["CH_Size"].astype(int)
df["SH_Size"] = df["SH_Size"].astype(int)

rows = []

for label, group in df.groupby("label"):
    mean_CH = group["CH_Size"].mean()
    std_CH  = group["CH_Size"].std()

    mean_SH = group["SH_Size"].mean()
    std_SH  = group["SH_Size"].std()

    rows.append({
        "label": label,
        "mean_CH ± std": f"{mean_CH:.2f} ± {std_CH:.2f}",
        "mean_SH ± std": f"{mean_SH:.2f} ± {std_SH:.2f}",
    })

result = pd.DataFrame(rows)
result.to_csv("updated_ch_sh_stats.csv", index=False)

print(result)
