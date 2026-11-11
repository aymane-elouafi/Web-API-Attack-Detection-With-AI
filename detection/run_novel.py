"""Held-out test: payloads that are NOT in the generator's catalogue (traffic/payloads.py).

The normal evaluation re-uses the same ~30 attack strings for training and testing, so it is
optimistic for both our rules and the ML model. Here the model is trained on the full dataset
and tested on fresh hand-written attacks and harmless look-alikes.

    python -m detection.run_novel [--data data/dataset.csv]
"""
import argparse
import json
from urllib.parse import quote

import pandas as pd

from detection.ml_payload import THRESHOLD, fit_full, prepare
from detection.report import pct
from detection.rules import THRESHOLD as RULE_THRESHOLD, stateless_hits

SQLI = ["1' OR '1'='1' /*", "admin' OR 1=1#", "x' UNION ALL SELECT NULL,NULL,NULL--",
        "' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--", "') UNION SELECT username||':'||password FROM users--",
        "1 AND (SELECT 1 FROM (SELECT SLEEP(3))a)", "'||(SELECT name FROM sqlite_master)||'", "\" OR \"\"=\"",
        "1 OR 1=1", "' AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='a'--", "admin'/**/OR/**/1=1--",
        "1; SELECT pg_sleep(5)--"]
XSS = ["<svg onload=confirm(1)>", "<img src=1 onerror=prompt(document.domain)>", "<marquee onstart=alert(1)>",
       "<video><source onerror=alert(1)>", "'-alert(1)-'", "<script>eval(atob('YWxlcnQoMSk='))</script>",
       "<object data=javascript:alert(1)>", "<body onpageshow=alert(1)>", "<math><mi xlink:href=javascript:alert(1)>x</mi></math>",
       "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>"]
TRAVERSAL = ["..%c0%af..%c0%afetc/passwd", "/var/www/../../etc/passwd", "....\\....\\windows\\win.ini",
             "%2e%2e%5c%2e%2e%5cetc%5cpasswd", "file:///etc/passwd", "/proc/self/environ", "..;/..;/etc/passwd",
             "php://filter/read=convert.base64-encode/resource=index.php"]
# Harmless text that merely looks suspicious
BENIGN_SEARCH = ["O'Brien", "select series keyboard", "union station tickets", "how to drop shipping", "50% off & free shipping",
                 "price > 100 and < 200", "it's 5 o'clock", "a -- b", "men's size 10", "C:\\Users manual"]
BENIGN_COMMENT = ["I <3 this product", "5 > 3 and 2 < 4", "Great -- would buy again", "Don't select the cheap one; it's slow", "see you at 10 o'clock"]


def requests() -> pd.DataFrame:
    rows = [("GET", "/products/search", "q=" + quote(p, safe=""), "", "sqli") for p in SQLI]
    rows += [("POST", "/comments", "", json.dumps({"text": p}), "xss") for p in XSS]
    rows += [("GET", "/files", "name=" + p, "", "path_traversal") for p in TRAVERSAL]
    rows += [("GET", "/products/search", "q=" + quote(p, safe=""), "", "normal") for p in BENIGN_SEARCH]
    rows += [("POST", "/comments", "", json.dumps({"text": p}), "normal") for p in BENIGN_COMMENT]
    df = pd.DataFrame(rows, columns=["method", "path", "query", "body", "attack_type"])
    df["label"] = (df.attack_type != "normal").astype(int)
    return df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    args = ap.parse_args()

    train = pd.read_csv(args.data, keep_default_na=False)
    model = fit_full(train)

    test = requests()
    t_texts, t_nums = prepare(test)
    test["ml_prob"] = model.score(t_texts, t_nums)
    test["ml"] = test.ml_prob >= THRESHOLD
    test["rules"] = [sum(s for _, s in stateless_hits(r.query, r.body)) >= RULE_THRESHOLD for r in test.itertuples()]

    print(f"Held-out test: {int(test.label.sum())} novel attacks, {int((test.label == 0).sum())} harmless look-alikes\n")
    out = {}
    for kind, g in test.groupby("attack_type"):
        label = "false alarms (lower is better)" if kind == "normal" else "caught"
        out[kind] = {"n": len(g), "metric": label, "payload ML": f"{g.ml.sum()}/{len(g)}", "own rules": f"{g.rules.sum()}/{len(g)}"}
    print(pd.DataFrame(out).T.to_string())
    atk = test[test.label == 1]
    print(f"\nOverall attack recall:  payload ML {pct(atk.ml.mean())}   own rules {pct(atk.rules.mean())}")
    print(f"Overall false alarms:   payload ML {int(test[test.label == 0].ml.sum())}   own rules {int(test[test.label == 0].rules.sum())}")

    for name in ("ml", "rules"):
        bad = test[(test[name] != (test.label == 1))]
        print(f"\n{name}: wrong on {len(bad)}")
        for r in bad.itertuples():
            print(f"  [{r.attack_type}] p={r.ml_prob:.2f} {r.path}?{r.query} {r.body}"[:150])


if __name__ == "__main__":
    main()
