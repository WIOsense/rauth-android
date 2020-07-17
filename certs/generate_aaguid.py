#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import os
import base64
import sys
import argparse

def make_aaguid(random=True):
    bytesAaguid = bytearray()

    if (random):
        for i in range(0,16):
            randomByte = ord(os.urandom(1)) % 255
            bytesAaguid.append(randomByte)
    else:
        bytesAaguid = bytearray([0]*16)

    return (bytesAaguid, base64.b64encode(bytesAaguid))
    
def update_aaguid(aaguid):
    code = os.path.abspath("../src/main/java/de/wiosense/webauthn/models/AuthenticatorConfig.java")
    contents = []
    with open(code, "r") as aaguid_file:
        line_num = 0
        pos = 0
        for line in aaguid_file:
            if ("byte[] AAGUID =" in line):
                pos = line_num + 1
            line_num += 1
            contents.append(line)
    
    contents.pop(pos)
    contents.insert(pos, "            \"" + aaguid + "\"" + ",\n")
    print("\n" + "".join(contents))
    
    with open(code, "w") as aaguid_file:
        aaguid_file.writelines(contents)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility to handle generation/update of new batch AAGUIDs")
    parser.add_argument("-r", "--randomized", action="store_true", help="Generates a randomized AAGUID (default false). If not specified AAGUID is 16 bytes of 0s")
    parser.add_argument("-u", "--update", action="store_true", help="Updates the code with the new AAGUID (default false).")
    args = parser.parse_args()

    bytesAaguid, b64Aaguid = make_aaguid(args.randomized)
    print("Generated AAGUID is:")
    print("\tBytes format: ", bytesAaguid)
    print("\tBase64 format: ", b64Aaguid)

    if (args.update):
        update_aaguid(b64Aaguid.decode("utf-8"))
