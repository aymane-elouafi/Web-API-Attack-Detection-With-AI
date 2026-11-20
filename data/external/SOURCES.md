# External datasets (downloaded 2026-11-20, approved by the user; not committed: `data/external/` is git-ignored)

| Folder | What | Source | Downloaded | License note |
|---|---|---|---|---|
| `csic2010/` | CSIC 2010 HTTP dataset, `csic_2010_processed.csv` (61k rows, 36k normal / 25k anomalous before de-duplication). **Held out: never used for training.** | Hugging Face mirror https://huggingface.co/datasets/arbk2023/csic_2010 (the `bridge4/...` mirror only offers parquet and its rows API returned 502; the original CSIC site was unreachable). Original: https://www.tic.itefi.csic.es/dataset/ | 30.7 MB | No explicit license; research dataset by CSIC (Spain). Cite: Gimenez, Villegas, Marañón (2010). |
| `fwaf/` | FWAF `badqueries.txt` (48k lines) and `goodqueries.txt` (1.29M lines) | https://github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall (shallow clone, commit 9c92866) | 38 MB on disk | No license in the repo; coursework use only. **Label noise:** `goodqueries.txt` contains scanner probes (remote-include URLs, `cmd=ls`), see `detection/external_data.py`. |
| `patt/` | PayloadsAllTheThings: SQL Injection, XSS Injection, Directory Traversal, Command Injection (sparse checkout, commit 08ea40e) | https://github.com/swisskyrepo/PayloadsAllTheThings | 5.3 MB | MIT |
| `seclists/` | SecLists `Fuzzing/` (sparse checkout, XSS, LFI and top-level lists only, commit 1a89b46) | https://github.com/danielmiessler/SecLists | 21 MB | MIT |
| `crs/` | OWASP CRS `tests/regression` (sparse checkout, commit 2de4afc) | https://github.com/coreruleset/coreruleset | 5.4 MB | Apache-2.0 |

Not downloaded: SR-BH 2020 (436 MB, declined), HttpParams, other mirrors.
