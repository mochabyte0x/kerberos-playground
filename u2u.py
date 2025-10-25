# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
TGS-REQ U2U Ticket Request Utility script
Author: mochabyte
"""

from __future__ import annotations

import os
import sys
import random
import argparse
import datetime
from pathlib import Path
from typing import Optional, Sequence, Tuple

from pyasn1.type.univ import noValue
from pyasn1.error import PyAsn1Error
from pyasn1.codec.der import decoder, encoder

from impacket.krb5 import constants  
from impacket.krb5.asn1 import ( 
    AP_REQ,
    AS_REP,
    Authenticator,
    EncTGSRepPart,
    TGS_REP,
    TGS_REQ,
    Ticket as TicketAsn1,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.ccache import CCache  
from impacket.krb5.kerberosv5 import sendReceive  
from impacket.krb5.crypto import Key, _enctype_table 
from impacket.krb5.types import KerberosTime, Principal, Ticket 

VERBOSE = False

def INF(message: str) -> None:
    print(f"[+] {message}")


def DBG(message: str) -> None:
    if VERBOSE:
        print(f"[DEBUG] {message}")


def ERR(message: str) -> None:
    print(f"[!] {message}")

DEFAULT_ETYPES = (
    constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
    constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
    constants.EncryptionTypes.rc4_hmac.value,
)


def decode_bytes(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def guess_principal_type(value: str) -> int:
    if "/" in value:
        return constants.PrincipalNameType.NT_SRV_INST.value
    if "@" in value:
        return constants.PrincipalNameType.NT_ENTERPRISE.value
    return constants.PrincipalNameType.NT_PRINCIPAL.value


def load_client_tgt(cache_path: Path, realm_hint: Optional[str]) -> Tuple[str, dict]:
    cache = CCache.loadFile(str(cache_path))
    if cache is None:
        raise ValueError(f"Could not read client ccache '{cache_path}'.")

    cache_realm = decode_bytes(cache.principal.realm["data"]).upper()
    realm = (realm_hint or cache_realm).upper()
    if not realm:
        raise ValueError("Unable to determine Kerberos realm. Try with --realm.")

    krbtgt_name = f"krbtgt/{realm}@{realm}"
    credential = cache.getCredential(krbtgt_name)
    if credential is None:
        for cred in cache.credentials:
            server = decode_bytes(cred["server"].prettyPrint()).upper()
            if server.startswith("KRBTGT/"):
                credential = cred
                DBG(f"Using fallback TGT from cache entry {server}")
                break

    if credential is None:
        raise ValueError(f"No TGT for {realm} found inside {cache_path}.")

    return realm, credential.toTGT()


def load_additional_ticket(
    cache_path: Path, principal_hint: Optional[str]
) -> Tuple[TicketAsn1, str]:

    cache = CCache.loadFile(str(cache_path))
    if cache is None:
        raise ValueError(f"Could not read additional ccache '{cache_path}'.")

    credential = None
    if principal_hint:
        credential = cache.getCredential(principal_hint)

    if credential is None and cache.credentials:
        credential = cache.credentials[0]

    if credential is None:
        raise ValueError(f"No credentials found inside {cache_path}.")

    asn1_ticket = decoder.decode(
        credential.ticket["data"], asn1Spec=TicketAsn1()
    )[0]
    ticket = Ticket()
    ticket.from_asn1(asn1_ticket)
    owner = decode_bytes(credential["client"].prettyPrint())
    return ticket.to_asn1(TicketAsn1()), owner


def encode_tgs_req(
    server_name: Principal,
    realm: str,
    tgt_bundle: dict,
    additional_ticket: TicketAsn1,
    etypes: Sequence[int],
    renewal: bool,
) -> bytes:

    tgt_data = tgt_bundle["KDC_REP"]
    cipher = tgt_bundle["cipher"]
    session_key = tgt_bundle["sessionKey"]

    try:
        decoded_tgt = decoder.decode(tgt_data, asn1Spec=AS_REP())[0]
    except PyAsn1Error:
        decoded_tgt = decoder.decode(tgt_data, asn1Spec=TGS_REP())[0]

    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = decoded_tgt["crealm"].asOctets()

    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")
    seq_set(authenticator, "cname", client_name.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)
    encrypted_authenticator = cipher.encrypt(session_key, 7, encoded_authenticator, None)

    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_authenticator

    encoded_ap_req = encoder.encode(ap_req)

    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req["padata"][0]["padata-value"] = encoded_ap_req

    req_body = seq_set(tgs_req, "req-body")

    opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.renewable_ok.value,
        constants.KDCOptions.canonicalize.value,
        constants.KDCOptions.enc_tkt_in_skey.value,
    ]
    if renewal:
        opts.append(constants.KDCOptions.renew.value)

    req_body["kdc-options"] = constants.encodeFlags(opts)
    seq_set(req_body, "sname", server_name.components_to_asn1)
    req_body["realm"] = realm.upper()

    till = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    req_body["till"] = KerberosTime.to_asn1(till)
    req_body["nonce"] = random.getrandbits(31)

    seq_set_iter(req_body, "etype", tuple(int(e) for e in etypes))
    seq_set_iter(req_body, "additional-tickets", (additional_ticket,))

    return encoder.encode(tgs_req)


def request_u2u_ticket(
    server_name: Principal,
    realm: str,
    kdc_host: Optional[str],
    tgt_bundle: dict,
    additional_ticket: TicketAsn1,
    etypes: Sequence[int],
    renewal: bool,
) -> Tuple[bytes, Key, Key]:

    message = encode_tgs_req(
        server_name, realm, tgt_bundle, additional_ticket, etypes, renewal
    )
    response = sendReceive(message, realm, kdc_host)

    cipher = tgt_bundle["cipher"]
    session_key = tgt_bundle["sessionKey"]

    tgs = decoder.decode(response, asn1Spec=TGS_REP())[0]
    cipher_text = tgs["enc-part"]["cipher"]
    plain_text = cipher.decrypt(session_key, 8, cipher_text)
    enc_part = decoder.decode(plain_text, asn1Spec=EncTGSRepPart())[0]

    new_session_key = Key(
        enc_part["key"]["keytype"], enc_part["key"]["keyvalue"].asOctets()
    )
    new_cipher = _enctype_table[enc_part["key"]["keytype"]]

    return response, new_cipher, new_session_key


def save_ticket(output_path: Path, tgs_bytes: bytes, old_session_key: Key, new_session_key: Key):
    cache = CCache()
    cache.fromTGS(tgs_bytes, old_session_key, new_session_key)
    cache.saveFile(str(output_path))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send a U2U TGS-REQ that embeds an additional TGT"
    )
    parser.add_argument(
        "-s",
        "--service",
        required=True,
        help="Target SPN/UPN (e.g. user@domain or cifs/server)",
    )
    parser.add_argument(
        "-c",
        "--client-ccache",
        default=os.environ.get("KRB5CCNAME"),
        help="Client ccache containing the authenticating TGT (default: KRB5CCNAME)",
    )
    parser.add_argument(
        "-a",
        "--additional-ccache",
        required=True,
        help="'Server' ccache that holds the additional TGT to put in additional-tickets",
    )
    parser.add_argument(
        "--additional-principal",
        help="Specific principal to pull from the additional cache (defaults to the first credential)",
    )
    parser.add_argument(
        "-r",
        "--realm",
        help="Kerberos realm/AD domain (defaults to the realm from the client cache)",
    )
    parser.add_argument("--dc-ip", help="KDC IP/hostname override")
    parser.add_argument(
        "--etype",
        action="append",
        type=int,
        help="Extra encryption type IDs to request (can be repeated)",
    )
    parser.add_argument(
        "--save",
        help="Path to write the resulting service ticket as a ccache",
    )
    parser.add_argument(
        "--renew",
        action="store_true",
        help="Set the RENEW option in the TGS-REQ",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    if not args.client_ccache:
        parser.error("client ccache not found. Set KRB5CCNAME or use -c.")

    return args


def main():
    args = parse_args()

    
    global VERBOSE
    VERBOSE = bool(args.debug)

    client_cache_path = Path(args.client_ccache).expanduser()
    additional_cache_path = Path(args.additional_ccache).expanduser()

    realm, tgt_bundle = load_client_tgt(client_cache_path, args.realm)
    addl_ticket, addl_owner = load_additional_ticket(
        additional_cache_path, args.additional_principal
    )

    service = Principal(
        args.service,
        type=guess_principal_type(args.service),
        default_realm=realm,
    )

    etypes = list(DEFAULT_ETYPES)
    cipher_enctype = tgt_bundle["cipher"].enctype
    if cipher_enctype not in etypes:
        etypes.append(cipher_enctype)
    if args.etype:
        etypes.extend(int(e) for e in args.etype)

    INF(
        f"Requesting U2U ticket for {service} using realm {realm} "
        f"and additional ticket owned by {addl_owner or 'unknown principal'}"
    )

    tgs_bytes, new_cipher, new_session_key = request_u2u_ticket(
        service,
        realm,
        args.dc_ip,
        tgt_bundle,
        addl_ticket,
        etypes,
        args.renew,
    )

    try:
        enctype_name = constants.EncryptionTypes(new_session_key.enctype).name
    except ValueError:
        enctype_name = str(new_session_key.enctype)

    INF(f"Received ticket encrypted with {enctype_name}")

    if args.save:
        output_path = Path(args.save).expanduser()
        save_ticket(output_path, tgs_bytes, tgt_bundle["sessionKey"], new_session_key)
        INF(f"Saved service ticket to {output_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        ERR(f"U2U request failed: {exc}")
        sys.exit(1)
