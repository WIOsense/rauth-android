#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import argparse
import os

cert_dict = {
    "ws": "WEBAUTH_BATCH_ATTESTATION_SIGNING_KEY",
    "wp": "WEBAUTHN_BATCH_ATTESTATION_CERTIFICATE",
    "us": "U2F_AUTHENTICATION_BATCH_SIGNING_KEY",
    "up": "U2F_AUTHENTICATION_BATCH_CERTIFICATE"
}

def retrieve_pem(pem_file):
    with open(pem_file, "r") as pem:
        pem_out = []
        for line in pem:
            line = line.replace("\n","")
            line = "            \"" + line + "\\n\" +\n"
            pem_out.append(line)
        pem_out[-1] = pem_out[-1].replace(" +",";")
    return pem_out

def update_current_pem(content, line_num, new_content):
    pos = line_num
    to_write = 0
    while (";" not in content[pos]):
        content.pop(pos)
    content.pop(pos)
    
    while(to_write < len(new_content)):
        content.insert(pos, new_content[to_write])
        pos += 1
        to_write += 1
    return content

def update_pem(content, key, new_content):
    line_num = 0
    for line in content:
        if (key in line):
            break
        line_num += 1
    
    return update_current_pem(content, line_num+1, new_content)

def update_certs(new_content):
    code = os.path.abspath("../src/main/java/de/wiosense/webauthn/models/AuthenticatorCerts.java")
    print("".join(new_content))
    with open(code, "w") as pem:
        pem.writelines(new_content)

def load_certs():
    code = os.path.abspath("../src/main/java/de/wiosense/webauthn/models/AuthenticatorCerts.java")
    with open(code, "r") as reader:
        certs = []
        for line in reader:
            certs.append(line)
    return certs

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility to update batch attestation certificates")
    parser.add_argument("--ws", help="Path to WebAuthn batch attestation private key PKCS8 PEM file")
    parser.add_argument("--wp", help="Path to WebAuthn batch attestation certificate PEM file")
    parser.add_argument("--us", help="Path to U2F batch attestation private key PKCS8 PEM file")
    parser.add_argument("--up", help="Path to U2F batch attestation certificate PEM file")
    args = parser.parse_args()

    certs = load_certs()

    if args.ws:
        update_pem(certs, cert_dict["ws"], retrieve_pem(args.ws))

    if args.wp:
        update_pem(certs, cert_dict["wp"], retrieve_pem(args.wp))

    if args.up:
        update_pem(certs, cert_dict["up"], retrieve_pem(args.up))

    if args.us:
        update_pem(certs, cert_dict["us"], retrieve_pem(args.us))

    update_certs(certs)
