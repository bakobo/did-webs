#!/usr/bin/env bash
set -euo pipefail

# Start `uv run kli witness demo --base "$m7_base" --version 1.0` separately
# before `create`, and keep it running through `rotate`.
m7_action=${1:?Use create or rotate.}
m7_base=${2:?Supply a fresh KLI base name.}
m7_host=${3:-dids.bakobo.com}
m7_output=${4:-.ignored/m7}
m7_prefix=${5:-demo}
m7_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$m7_root"

if [[ "$m7_action" == create ]]; then
  for m7_name in reissuer guy; do
    nice -n 19 ionice -c 3 uv run kli init --name "$m7_name" --base "$m7_base" \
      --nopasscode --config-dir "$m7_root/scripts" --config-file m7-witness-oobis \
      --version 1.0
    nice -n 19 ionice -c 3 uv run python scripts/sedi_m7_keri.py seed \
      --name "$m7_name" --base "$m7_base"
    nice -n 19 ionice -c 3 uv run kli incept --name "$m7_name" --base "$m7_base" \
      --alias "$m7_name" --file "$m7_root/scripts/m7-incept.json" \
      --receipt-endpoint --version 1.0
    nice -n 19 ionice -c 3 uv run python scripts/sedi_m7_keri.py issue \
      --name "$m7_name" --base "$m7_base" --host "$m7_host" --path-prefix "$m7_prefix"
  done
elif [[ "$m7_action" == rotate ]]; then
  nice -n 19 ionice -c 3 uv run kli rotate --name guy --base "$m7_base" \
    --alias guy --receipt-endpoint --version 1.0
else
  printf 'Use create or rotate.\n' >&2
  exit 64
fi

if [[ "$m7_action" == create ]]; then
  m7_names=(reissuer guy)
else
  m7_names=(guy)
fi
for m7_name in "${m7_names[@]}"; do
  m7_aid=$(nice -n 19 ionice -c 3 uv run python scripts/sedi_m7_keri.py export \
    --name "$m7_name" --base "$m7_base" --stream "$m7_output/streams/$m7_name.cesr")
  nice -n 19 ionice -c 3 uv run didwebs publish \
    --stream "$m7_output/streams/$m7_name.cesr" \
    --did "did:webs:$m7_host:$m7_prefix:$m7_aid" --out "$m7_output/artifacts"
done
