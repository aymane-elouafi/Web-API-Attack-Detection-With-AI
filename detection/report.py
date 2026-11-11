"""Printable evaluation report, shared by every detector."""
import pandas as pd

from detection import metrics

pd.set_option("display.width", 200, "display.max_colwidth", 80)


def pct(x: float) -> str:
    return f"{x:.1%}"


def print_report(df: pd.DataFrame, title: str, flag: str, score: str, hits: str) -> None:
    """df needs: label, attack_type, variant, method, path, query, body + the detector's
    boolean `flag` column, numeric `score` column and `hits` column (matched rule ids)."""
    m = metrics.overall(df, flag)
    print(f"{title}   {len(df)} requests\n")
    print(f"  caught {m['tp']} of {m['tp'] + m['fn']} attacks     missed {m['fn']}")
    print(f"  wrongly flagged {m['fp']} of {m['fp'] + m['tn']} normal requests")
    print(f"  precision {pct(m['precision'])}   recall {pct(m['recall'])}   "
          f"F1 {pct(m['f1'])}   false-positive rate {pct(m['fpr'])}")

    print("\nRecall by attack type:")
    t = metrics.by_attack_type(df, flag)
    t["recall"] = t["recall"].map(pct)
    print(t.to_string())

    print("\nRecall by evasion variant (how well disguised attacks do):")
    v = metrics.by_variant(df, flag)
    v["recall"] = v["recall"].map(pct)
    print(v.to_string())

    missed = df[(df.label == 1) & ~df[flag]]
    partial = missed[missed[score] > 0]
    print(f"\nMissed attacks that still scored something (suspicious, below threshold): "
          f"{len(partial)} of {len(missed)}")

    fps = df[(df.label == 0) & df[flag]]
    print(f"\nFalse positives ({len(fps)}):")
    if len(fps):
        print(fps.groupby(["method", "path", hits]).size().to_string())
    else:
        print("  none")

    print("\nExamples of missed attacks (up to 2 per type):")
    for kind, g in missed.groupby("attack_type"):
        for _, r in g.head(2).iterrows():
            print(f"  [{kind}/{r.variant}] score={r[score]} {r.method} {r.path}"
                  f"?{r.query} {r.body}"[:170])
