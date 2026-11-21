#!/bin/sh
# Train the AI models into the models volume if it is empty (first start on a fresh volume built from an old image, etc.).
set -e
dir="${WAFGW_MODELS:-models}"
if [ ! -f "$dir/payload.joblib" ] || [ ! -f "$dir/behavior.joblib" ]; then
  echo "entrypoint: no models in $dir, training from data/dataset.csv" >&2
  python -m wafgw.train --data data/dataset.csv --out "$dir"
fi
exec "$@"
