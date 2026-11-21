"""Offline check of the bot detector on data/dataset.csv: python -m wafgw.eval_bot

The dataset has no request headers, so only the User-Agent signatures and the rhythm rules are exercised here
(header anomalies are covered by unit tests and by the live gateway). Rows are replayed in time order.
"""
from collections import Counter

import pandas as pd

from wafgw.bot import BotDetector

ALERT = 0.5


def run(path: str = "data/dataset.csv") -> pd.DataFrame:
    df = pd.read_csv(path, keep_default_na=False).sort_values("ts")
    bot, rows = BotDetector(), []
    for r in df.itertuples():
        s, detail, entry = bot.inspect({"ts": r.ts, "client_ip": r.client_ip, "path": r.path, "user_agent": r.user_agent,
                                        "session": r.user})
        entry[2] = r.status                                   # what observe() does after the answer
        rows.append((r.id, s, detail))
    return df.merge(pd.DataFrame(rows, columns=["id", "bot", "bot_detail"]), on="id")


def main() -> None:
    df = run()
    attackers = set(df[df.label == 1].client_ip)
    normal, clean = df[df.label == 0], df[(df.label == 0) & ~df.client_ip.isin(attackers)]
    print(f"{len(df)} requests, {int(df.label.sum())} attacks, {len(normal)} normal ({len(clean)} from clients that never attacked)\n")
    for name, part in [("all normal requests", normal), ("normal requests of clean clients", clean)]:
        print(f"false alarms, {name}: {int((part.bot >= ALERT).sum())} of {len(part)} ({(part.bot >= ALERT).mean():.1%}); "
              f"any weak signal (>0): {(part.bot > 0).mean():.1%}")
    print("\nnormal-request findings:", dict(Counter(p.split(':')[0] for d in normal.bot_detail if d for p in d.split('; '))))
    print("\nrecall at alert level (>= 0.5) by attack type:")
    atk = df[df.label == 1]
    print((atk.groupby("attack_type").bot.apply(lambda s: (s >= ALERT).mean()).map("{:.1%}".format)).to_string())
    tool = atk[atk.user_agent.str.contains("sqlmap|nikto|hydra", case=False)]
    print(f"\nscanner-tool sessions (tool User-Agent): {len(tool)} requests, caught {(tool.bot >= ALERT).mean():.0%}" if len(tool) else "")
    fast = atk[atk.attack_type == "brute_force"]
    print(f"brute-force rows flagged by rhythm only (no tool UA): {int(((fast.bot >= ALERT) & ~fast.user_agent.str.contains('hydra', case=False)).sum())} of {len(fast)}")


if __name__ == "__main__":
    main()
