#!/usr/bin/env python3
"""Independent verifier for NameWheel TrueSpin certified draws.

Recomputes, with no NameWheel code involved:
  1. the seed commitment      SHA-256 over the seed's hex text
  2. the winner               HMAC-SHA-256(seed bytes, entropy | entries hash)
  3. the entries hash         SHA-256 over the JSON-serialized entry list
  4. the video hash           SHA-256 over the hosted MP4, byte for byte

Usage:
  python verify.py NT49TV59            verify a draw by its code
  python verify.py NT49TV59 --no-video skip the video download

Protocol spec: https://namewheel.org/truespin-spec
Only Python 3 standard library. MIT licensed.
"""
import hashlib
import hmac
import json
import re
import sys
import urllib.request

API = "https://namewheel.org/api/draw/{}"


UA = {"User-Agent": "truespin-verifier/1.0 (+https://namewheel.org/truespin-spec)"}


def fetch(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA))


def fetch_json(url):
    with fetch(url) as r:
        return json.loads(r.read().decode("utf-8"))


def entries_hash(entries):
    # Byte-exact match for JavaScript's JSON.stringify(entries):
    # compact separators, unicode kept literal (not \u escaped), UTF-8 bytes.
    serialized = json.dumps(entries, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def tickets_of(entries):
    # A ":N" suffix is a weight: that entry holds N tickets, clamped 1..99.
    tickets = []
    for i, e in enumerate(entries):
        m = re.search(r":(\d+)$", e)
        w = max(1, min(99, int(m.group(1)))) if m else 1
        tickets.extend([i] * w)
    return tickets


def winner_index(seed_hex, entropy, entries):
    key = bytes.fromhex(seed_hex)
    msg = (entropy + "|" + entries_hash(entries)).encode("ascii")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    n = int.from_bytes(digest[:8], "big")
    tickets = tickets_of(entries)
    return tickets[n % len(tickets)]


def strip_weight(name):
    return re.sub(r":(\d+)$", "", name)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(1)
    code = re.sub(r"[^A-Z0-9]", "", args[0].upper())
    check_video = "--no-video" not in sys.argv

    print(f"fetching record for {code} ...")
    d = fetch_json(API.format(code))
    if not d.get("serverSeed"):
        sys.exit("draw exists but its seed is not revealed yet; nothing to verify")

    ok = True

    # 1. entries hash
    eh = entries_hash(d["entries"])
    good = eh == d["entriesHash"]
    ok &= good
    print(f"[{'PASS' if good else 'FAIL'}] entries hash    {eh}")

    # 2. commitment: SHA-256 of the seed's ASCII hex text
    commit = hashlib.sha256(d["serverSeed"].encode("ascii")).hexdigest()
    good = commit == d["commit"]
    ok &= good
    print(f"[{'PASS' if good else 'FAIL'}] commitment      {commit}")

    # 3. winner
    idx = winner_index(d["serverSeed"], d["clientEntropy"], d["entries"])
    name = strip_weight(d["entries"][idx])
    good = idx == d["winnerIndex"] and name == d["winner"]
    ok &= good
    print(f"[{'PASS' if good else 'FAIL'}] winner          index {idx} -> {name}")

    # 4. video hash
    if check_video and d.get("videoHash"):
        base = "https://cdn.namewheel.org/v" if d.get("cdn") else "https://namewheel.org/v/files"
        url = f"{base}/{code}.mp4"
        print(f"downloading video {url} ...")
        with fetch(url) as r:
            vh = hashlib.sha256(r.read()).hexdigest()
        good = vh == d["videoHash"]
        ok &= good
        print(f"[{'PASS' if good else 'FAIL'}] video hash      {vh}")

    print()
    if ok:
        print(f"ALL CHECKS PASSED. The record at namewheel.org/v/{code} is internally consistent:")
        print("the seed matches its pre-spin commitment, the winner follows from the")
        print("committed randomness, and the hosted video is the untouched original.")
    else:
        print("ONE OR MORE CHECKS FAILED. Do not trust this draw.")
        sys.exit(2)


if __name__ == "__main__":
    main()
