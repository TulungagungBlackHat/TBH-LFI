# TBH-LFI

<p align="center">
  <a href="https://github.com/TulungagungBlackHat/TBH-LFI/actions/workflows/ci.yml"><img src="https://github.com/TulungagungBlackHat/TBH-LFI/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/payload-safe-green.svg" alt="Safe payloads">
</p>

Local File Inclusion / path traversal detector. Tests whether a file parameter will fetch a well-known local file and leak its contents.

Part of the [Tulungagung Black Hat](https://github.com/TulungagungBlackHat) toolset.

## What It Checks

- Classic `../` traversal sequences in file parameters
- Leak of recognizable local file content (e.g. `/etc/passwd` markers)
- Status code and response size deltas

Payloads target **public OS files only** — no application code, no databases, no user data. A hit means the app fetches attacker-influenced paths; escalation (RCE via wrappers) is a manual step left to you.

## Install

```bash
git clone https://github.com/TulungagungBlackHat/TBH-LFI
cd TBH-LFI
pip install -r requirements.txt
```

## Usage

```
usage: lfi.py [-h] -u URL [--json JSON]

options:
  -u, --url URL     Target URL with a file parameter
  --json JSON       Save result as JSON
```

```bash
python3 lfi.py -u "https://example.com/page?file=index" --json result.json
```

## Sample Output

```
[*] Testing https://example.com/page?file=index
[!] LFI: local file content reflected -> confirm manually
[✓] JSON: result.json
```

## Authorized Use Only

Only against scopes you own or are authorized to test. See [SECURITY.md](SECURITY.md).

## Related Tools

- [TBH-SSRF](https://github.com/TulungagungBlackHat/TBH-SSRF) — server-side fetch abuse, related bug class
- [TBH-AllScan](https://github.com/TulungagungBlackHat/TBH-AllScan) — LFI plus 9 other modules

## License

[MIT](LICENSE) — Tulungagung Black Hat, East Java, Indonesia. Always Smile :)
