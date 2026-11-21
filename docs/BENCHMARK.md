# Benchmark: our detectors vs Coraza + OWASP CRS

Coraza + CRS is the engine behind ModSecurity-based products such as BunkerWeb, so this is the fairest stand-in we can run
locally. SafeLine's engine is closed-source and not included. Reproduce with `python -m detection.benchmark` (see the module
docstring for the four Coraza containers; about 4 minutes).

## How to read it

* **Fair part:** every detector scores the same held-out requests (CSIC 2010), none of which was used for training or tuning.
* **Not like-for-like:** our schema detector LEARNS the application (half of the normal traffic here, or an OpenAPI spec). CRS is
  generic and learns nothing. That is a real product advantage of positive security, but it needs that learning traffic. The row
  "rules + payload model (no app learning)" is the like-for-like comparison with CRS.
* **CRS paranoia levels trade precision for recall:** level 1 is quiet and weak; levels 3-4 catch most anomalies only by flagging
  most normal requests too, which nobody can run in blocking mode.
* **CSIC is an old, single-application dataset** (a Spanish shop, 2010) and 87% of its anomalies are structural (tampered parameters,
  odd paths) rather than classic payloads. It says little about modern API attacks, and the CRS side got synthetic browser headers
  because CSIC keeps none. Nothing here is a claim about SafeLine, about production traffic, or about performance.

## Results

CSIC 2010, held-out: 4817 unseen normal + 15426 anomalous requests (de-duplicated).

```
                                                  recall precision  false alarms                                      notes
detector                                                                                                                   
Coraza + CRS, paranoia 1                           23.1%     99.9%      2 (0.0%)             BunkerWeb / ModSecurity engine
Coraza + CRS, paranoia 2                           37.7%     88.6%   750 (15.6%)             BunkerWeb / ModSecurity engine
Coraza + CRS, paranoia 3                           78.0%     77.8%  3424 (71.1%)             BunkerWeb / ModSecurity engine
Coraza + CRS, paranoia 4                           92.9%     76.8%  4329 (89.9%)             BunkerWeb / ModSecurity engine
our rules                                          14.9%    100.0%      0 (0.0%)                                           
our payload model (parser tokens + n-grams)        24.4%     99.9%      4 (0.1%)                                           
our schema detector (learned from 50% of normals)  82.5%    100.0%      6 (0.1%)                                           
ours: rules + payload model (no app learning)      28.5%     99.9%      4 (0.1%)                                           
ours: rules + payload model + schema (full)        87.4%     99.9%     14 (0.3%)  needs learning traffic or an OpenAPI spec
```

Recall by anomaly type (type guessed from the text by regex, only for reporting):

```
                             count CRS PL1 CRS PL2 CRS PL3 CRS PL4 ours (full)
kind                                                                          
path_traversal                 134  100.0%  100.0%  100.0%  100.0%      100.0%
sqli                           864   86.1%  100.0%  100.0%  100.0%      100.0%
structural (no attack text)  13476   12.9%   28.7%   74.8%   91.9%       85.6%
xss                            952  100.0%  100.0%  100.0%  100.0%      100.0%
```
