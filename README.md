# Check Point SSL-VPN Login Replicator

Python client that mirrors the browser-side Check Point SSL-VPN login flow for authorized assessment and response analysis. RSA material is **not** included; the script extracts the modulus and exponent from a `JS_RSA.js` file you supply.

## Quickstart
- Install deps: `pip install -r requirements.txt`
- Fetch the target portal's `JS_RSA.js` (e.g., from the login page resources) and place it beside the script or pass its path with `--rsa-file`.
- Prepare username and password lists (one entry per line).
- Run: `python3 checkforcer.py -h vpn.example.com -u users.txt -p passwords.txt --rsa-file ./JS_RSA.js -o results.jsonl`

## Notes
- Outputs line-oriented JSON with user, password, encrypted payload, HTTP status, and parsed attributes.
- Requires PKCS#1 v1.5 padding; the RSA key is derived at runtime from the provided `JS_RSA.js`.
- Use only against systems you are authorized to test; disable certificate verification is intentional for lab work—adjust as needed.
