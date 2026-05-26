#!/usr/bin/env python3
r"""
krbkeys.py — Derive Kerberos AES keys and NT hash for any AD account type

ACCOUNT TYPES & SALT FORMULAS:
    User account     salt = REALM + sAMAccountName
                     password input: plaintext string

    Computer/gMSA    salt = REALM + "host" + name_without_$.lower() + "." + domain.lower()
                     password input: raw bytes as --hex or --b64
                     AES derivation: requires aesKrbKeyGen (impacket gives wrong keys)

    Auto-detection:  if sAMAccountName ends with '$' → computer/gMSA salt format
                     otherwise → user salt format

IMPORTANT — gMSA / COMPUTER AES KEYS:
    impacket's string_to_key gives WRONG AES keys for computer and gMSA accounts.
    The correct derivation requires aesKrbKeyGen (Tw1sm/aesKrbKeyGen on GitHub).
    For regular user accounts, impacket works correctly.

    Always verify the salt by capturing a failing AS-REQ in Wireshark:
    KRB-ERROR → e-data → PA-ETYPE-INFO2 → ETYPE-INFO2-ENTRY → salt field

PRE-REQUISITES:
    pip install impacket          # NT hash + user AES keys
    # For computer/gMSA AES keys (required):
    git clone https://github.com/Tw1sm/aesKrbKeyGen
    # Place aesKrbKeyGen.py in PATH or same directory as this script

USAGE:
    # Regular user account (plaintext password)
    python3 krbkeys.py -u COOLIO -d DOMAIN.LOCAL -p '<PW>'

    # Computer account (hex password bytes from e.g. secretsdump)
    python3 krbkeys.py -u 'DC1$' -d DOMAIN.LOCAL --hex <512_hex_chars>

    # gMSA account (B64ENCODED from bloodyAD msDS-ManagedPassword)
    echo "<B64>" | python3 krbkeys.py -u 'GMSA$' -d DOMAIN.LOCAL --b64

    # Force a specific salt (e.g. after reading it from Wireshark)
    python3 krbkeys.py -u 'GMSA$' -d DOMAIN.LOCAL --b64 "<B64>" \
        --salt 'DOMAIN.LOCALgmsa.domain.local'
"""

import argparse
import base64
import hashlib
import os
import subprocess
import sys


# ── Salt derivation ───────────────────────────────────────────────────────────

def detect_type(sam: str, forced: str = None) -> str:
    """Return 'computer' or 'user' based on sAMAccountName or forced flag."""
    if forced:
        return forced
    return 'computer' if sam.endswith('$') else 'user'


def build_salt(domain: str, sam: str, acct_type: str) -> str:
    """
    Derive Kerberos salt.
      user:     REALM + sAMAccountName
      computer: REALM + host + name.lower() + . + domain.lower()
    """
    realm = domain.upper()
    if acct_type == 'computer':
        name = sam.rstrip('$').lower()
        return f"{realm}host{name}.{domain.lower()}"
    else:
        return f"{realm}{sam}"


# ── Password input ────────────────────────────────────────────────────────────

def resolve_password(args) -> tuple[bytes | None, str | None]:
    """
    Return (raw_bytes, plaintext_str).
    Exactly one of them will be set depending on input mode.
    """
    if args.password:
        return None, args.password

    b64_src = None
    if args.b64:
        b64_src = args.b64 if args.b64 != '-' else None
    if args.b64 is not None and b64_src is None and not sys.stdin.isatty():
        b64_src = sys.stdin.read().strip()

    if b64_src:
        try:
            return base64.b64decode(b64_src), None
        except Exception as e:
            print(f"[!] B64 decode failed: {e}", file=sys.stderr)
            sys.exit(1)

    if args.hex:
        hex_src = args.hex if args.hex != '-' else sys.stdin.read().strip()
        try:
            return bytes.fromhex(hex_src), None
        except Exception as e:
            print(f"[!] Hex decode failed: {e}", file=sys.stderr)
            sys.exit(1)

    # Stdin without explicit flag — try B64 then hex
    if not sys.stdin.isatty():
        raw_input = sys.stdin.read().strip()
        try:
            decoded = base64.b64decode(raw_input)
            if len(decoded) in (256, 128):
                return decoded, None
        except Exception:
            pass
        try:
            return bytes.fromhex(raw_input), None
        except Exception:
            pass
        # Treat as plaintext password
        return None, raw_input

    return None, None


# ── NT hash ──────────────────────────────────────────────────────────────────

def compute_nt_hash(raw_bytes: bytes = None, plaintext: str = None) -> str:
    """
    NT hash:
      user:          MD4(password.encode('utf-16-le'))
      computer/gMSA: MD4(raw_bytes)
    """
    data = raw_bytes if raw_bytes is not None else plaintext.encode('utf-16-le')
    try:
        return hashlib.new('md4', data).hexdigest()
    except ValueError:
        try:
            from impacket.crypto import MD4
            h = MD4()
            h.update(data)
            return h.hexdigest()
        except ImportError:
            return "(MD4 unavailable — install impacket or use OpenSSL < 3.x)"


# ── AES key derivation ────────────────────────────────────────────────────────

def _find_aeskrbkeygen(explicit: str = None) -> str | None:
    if explicit and os.path.isfile(explicit):
        return explicit
    candidates = [
        'aesKrbKeyGen.py',
        os.path.join(os.path.dirname(__file__), 'aesKrbKeyGen.py'),
        os.path.join(os.path.dirname(__file__), 'aesKrbKeyGen/aesKrbKeyGen.py'),
        os.path.expanduser('~/aesKrbKeyGen/aesKrbKeyGen.py'),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    for d in os.environ.get('PATH', '').split(':'):
        p = os.path.join(d, 'aesKrbKeyGen.py')
        if os.path.isfile(p):
            return p
    return None


def aes_via_aeskrbkeygen(raw_bytes: bytes, salt: str,
                          script: str) -> tuple[str, str] | None:
    """Derive AES keys via aesKrbKeyGen. Parses salt to reconstruct -domain/-user/-host."""
    hex_pw = raw_bytes.hex()
    try:
        # salt = REALMhostNAME.domain 
        after_host  = salt.split('host', 1)[1]       
        host_part   = after_host.split('.', 1)[0] 
        domain_part = after_host.split('.', 1)[1]   
    except (IndexError, ValueError):
        return None

    cmd = [sys.executable, script,
           '-domain', domain_part, '-user', host_part, '-pass', hex_pw, '-host']
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    aes256 = aes128 = None
    for line in out.splitlines():
        if 'AES256' in line:
            aes256 = line.split(':')[-1].strip().lower()
        elif 'AES128' in line:
            aes128 = line.split(':')[-1].strip().lower()
    return (aes256, aes128) if aes256 and aes128 else None


def aes_via_impacket(password: bytes | str, salt: str) -> tuple[str, str] | None:
    try:
        from impacket.krb5.crypto import string_to_key
        pw = password if isinstance(password, bytes) else password.encode('utf-8')
        return (
            string_to_key(18, pw, salt).contents.hex(),
            string_to_key(17, pw, salt).contents.hex(),
        )
    except ImportError:
        return None


def derive_aes(raw_bytes: bytes | None, plaintext: str | None,
               salt: str, acct_type: str,
               aeskrbkeygen_path: str = None,
               force_impacket: bool = False) -> tuple[tuple, bool]:
    """
    Returns ((aes256, aes128), used_aeskrbkeygen).
    For computer/gMSA: tries aesKrbKeyGen first, falls back to impacket.
    For user:          uses impacket directly (correct for plaintext passwords).
    """
    if acct_type == 'computer' and not force_impacket:
        script = _find_aeskrbkeygen(aeskrbkeygen_path)
        if script and raw_bytes is not None:
            keys = aes_via_aeskrbkeygen(raw_bytes, salt, script)
            if keys:
                return keys, True
        # Fallback
        pw = raw_bytes if raw_bytes is not None else plaintext
        keys = aes_via_impacket(pw, salt)
        return keys, False
    else:
        pw = plaintext if plaintext is not None else raw_bytes
        keys = aes_via_impacket(pw, salt)
        return keys, True   # impacket is correct for users


# ── Output helpers ────────────────────────────────────────────────────────────

def print_section(title: str, *lines):
    print(f"\n[*] {title}")
    for line in lines:
        print(f"    {line}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Derive Kerberos AES keys and NT hash for any AD account",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Identity
    parser.add_argument('-u', '--user',   required=True,
                        help="sAMAccountName e.g. coolio.user  /  gMSA$  /  DC1$")
    parser.add_argument('-d', '--domain', required=True,
                        help="FQDN domain")
    parser.add_argument('--type', choices=['user', 'computer'], default=None,
                        help="Override auto-detection (default: '$' suffix → computer)")

    # Password input (mutually exclusive)
    pw_group = parser.add_mutually_exclusive_group()
    pw_group.add_argument('-p', '--password', metavar='PLAINTEXT',
                          help="Plaintext password (user accounts)")
    pw_group.add_argument('--hex', metavar='HEX',
                          help="Raw password bytes as hex string (computer/gMSA). "
                               "Use '-' to read from stdin")
    pw_group.add_argument('--b64', metavar='B64', nargs='?', const='-',
                          help="Raw password bytes as base64 (gMSA .B64ENCODED from bloodyAD). "
                               "Omit value or use '-' to read from stdin")

    # Salt override
    parser.add_argument('--salt', metavar='SALT',
                        help="Override computed salt (use after reading from Wireshark)")

    # Tool paths / behaviour
    parser.add_argument('--aeskrbkeygen', metavar='PATH',
                        help="Explicit path to aesKrbKeyGen.py")
    parser.add_argument('--impacket-only', action='store_true',
                        help="Force impacket for AES (skips aesKrbKeyGen; WRONG for computer/gMSA)")

    args = parser.parse_args()

    # ── Resolve inputs ────────────────────────────────────────────────────────
    raw_bytes, plaintext = resolve_password(args)

    if raw_bytes is None and plaintext is None:
        print("[!] No password provided. Use -p, --hex, --b64, or pipe via stdin.",
              file=sys.stderr)
        sys.exit(1)

    acct_type = detect_type(args.user, args.type)
    salt      = args.salt or build_salt(args.domain, args.user, acct_type)

    # ── Print summary ─────────────────────────────────────────────────────────
    print(f"\n  Account  : {args.user}")
    print(f"  Domain   : {args.domain}")
    print(f"  Type     : {acct_type}")
    print(f"  Salt     : {salt}")
    if not args.salt:
        print(f"  (verify salt: capture failing AS-REQ in Wireshark → KRB-ERROR → PA-ETYPE-INFO2)")

    # ── NT hash ───────────────────────────────────────────────────────────────
    nt = compute_nt_hash(raw_bytes, plaintext)
    print_section(
        "NT Hash",
        nt,
        f"PTH:  -hashes ':{nt}'",
    )

    # ── AES keys ──────────────────────────────────────────────────────────────
    keys, reliable = derive_aes(
        raw_bytes, plaintext, salt, acct_type,
        aeskrbkeygen_path=args.aeskrbkeygen,
        force_impacket=args.impacket_only,
    )

    if not reliable and acct_type == 'computer':
        print(f"\n[!] aesKrbKeyGen not found — impacket fallback used")
        print(f"    Keys below are likely WRONG for computer/gMSA accounts")
        print(f"    Install: git clone https://github.com/Tw1sm/aesKrbKeyGen")
        print(f"    Place aesKrbKeyGen.py alongside this script or in PATH")

    if keys:
        aes256, aes128 = keys
        print_section(
            "AES256-CTS-HMAC-SHA1-96",
            aes256,
            f"getTGT: -aesKey {aes256}",
        )
        print_section(
            "AES128-CTS-HMAC-SHA1-96",
            aes128,
            f"getTGT: -aesKey {aes128}",
        )
    else:
        print(f"\n[!] AES derivation failed. Install impacket or aesKrbKeyGen.")

    print()


if __name__ == '__main__':
    main()
