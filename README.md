# TrueSpin Verifier

Independent verifier for [NameWheel](https://namewheel.org) TrueSpin certified draws.
Feed it a draw code and it recomputes the entire draw from public data, offline,
with no NameWheel code involved. Only standard library, in your choice of
Python or Node.

Every certified spin at namewheel.org publishes a permanent proof record.
This tool checks that record the hard way:

1. **Entries hash.** SHA-256 over the JSON serialized entry list matches the record.
2. **Commitment.** SHA-256 over the revealed seed's hex text matches the hash
   the server published *before* the wheel moved.
3. **Winner.** HMAC-SHA-256 of the seed bytes over `entropy | entriesHash`,
   first 8 bytes as a big-endian integer, modulo the ticket count, lands on
   the recorded winner.
5. **Attempts.** Reports every certified draw the same host started against
   this exact entry list, including any started and never published. This is
   printed as INFO or WARN, never as a PASS or FAIL, because re-running a draw
   is a disclosure question rather than a cryptographic one.
4. **Video hash.** SHA-256 over the hosted MP4, byte for byte, matches the
   hash in the record. The video really is the untouched original.

## Usage

```
python verify.py NT49TV59
node verify.js NT49TV59
```

Add `--no-video` to skip the video download. Try it right now with `NT49TV59`,
a real public draw. Expected output:

```
[PASS] entries hash    2940378f4ef325f2ffb43303d714261e34965c66c5ce576dac7c314d721510ce
[PASS] commitment      9aaa418b091de20182f68c6fc4cd6cbf9f389eae3ec293e8e84981030c0a95b5
[PASS] winner          index 0 -> Emma
[PASS] video hash      0616cecf63bd475d62e43f6f02129e46c52afabdd69e85e65b72e3fb2db346b3

[INFO] attempts        1 (the only draw this host started with this entry list)

ALL CHECKS PASSED.
```

## What this proves, and what it does not

A full pass proves the draw ran over exactly the listed entries, that the
winner came from randomness sealed before the spin which neither the host nor
NameWheel could steer alone, and that the hosted video is unedited. It cannot
prove the entry list itself was collected fairly, or what a host did off the
record. The proof page, and this tool, list every certified draw the host started
against the same entry list, including ones started and never published,
precisely so that selective re-spinning is visible rather than hidden.

The full byte-level protocol specification lives at
[namewheel.org/truespin-spec](https://namewheel.org/truespin-spec).

## Verifying the record signature

Each record is also signed with Ed25519. The public key is served at
[namewheel.org/api/draw-key](https://namewheel.org/api/draw-key). The canonical
signed string and an `openssl pkeyutl` walkthrough are documented in the spec.

## License

MIT. The verifier is intentionally boring: read it in five minutes, run it in
one, or reimplement it from the spec in any language you trust more.
