#!/usr/bin/env bash

# This script generates the root CA and attestation certificate information
# for WioKeys used in order to verify the devices by default. Feel free
# to change it accordingly to your needs if other preferrences are required
#
# It uses openssl for all the crypto related operations

# We will use the prime256v1 curve as default for certificate generation
curve=prime256v1

#########################################################
#
# Begin root of trust self-signed key pair as the Root CA
#
#########################################################

# echo "Root CA creation"
# echo "==================================================="
# echo

# Root CA information
country="DE"
organization="WIOsense GmbH & Co. KG"
unit="U2F Software Attestation"
CN="wiosense.de"

# Generate the EC private key using a good source of randomness (preferably a TRNG) -> generate trngseed.bin at your own will

echo "Device signing key and attestation certificate"
echo "==================================================="
echo

# Generate EC private key 
openssl ecparam -genkey -name "$curve" -out u2f_device_key.pem -rand u2f_trngseed.bin

# Generate the EC private key also in PKCS8 format
openssl pkcs8 -topk8 -nocrypt -in u2f_device_key.pem -out u2f_device_key_pkcs8.pem

# Generate the EC private key also in DER format for handling in HEX 
openssl ec -in u2f_device_key_pkcs8.pem -outform DER -out u2f_device_key.der

# # Sign the request
# openssl x509 -req -days 3652  -in u2f_device_key.pem.csr -extfile u2f_v3.ext -CA root_cert.pem -CAkey root_key.pem -set_serial 01 -out u2f_device_cert.pem -sha256

# Generate a "signing request"
openssl req -new -key u2f_device_key_pkcs8.pem -out u2f_device_key.pem.csr -subj "/C=$country/O=$organization/OU=$unit/CN=$CN"

# Self-sign the request - is sufficient for Basic Attestation format - there is limited support for CA root
openssl x509 -req -days 3652 -in u2f_device_key.pem.csr -extfile u2f_v3.ext -signkey u2f_device_key.pem -out u2f_device_cert.pem -sha256

# Convert to smaller size format DER
openssl  x509 -in u2f_device_cert.pem  -outform der -out u2f_device_cert.der

# Verify the device certificate details
openssl x509 -in u2f_device_cert.pem -text -noout

echo "==================================================="
echo

#########################################################
#
# End attestation certificate key pair to go on device
#
#########################################################

#########################################################
#
# Begin verification of attestation key and certificate
#
#########################################################

echo "Verification step"
echo
echo "==================================================="
echo
echo "challenge device @ $RANDOM" > chal.txt
echo "challenge root @ $RANDOM" > chal_rootCA.txt

# check that they are valid key pairs
openssl dgst -sha256 -sign u2f_device_key_pkcs8.pem -out sig.txt chal.txt
openssl dgst -sha256 -verify  <(openssl x509 -in u2f_device_cert.pem  -pubkey -noout)  -signature sig.txt chal.txt

# openssl dgst -sha256 -sign root_key.pem -out sig_rootCA.txt chal_rootCA.txt
# openssl dgst -sha256 -verify  <(openssl x509 -in root_cert.pem  -pubkey -noout)  -signature sig_rootCA.txt chal_rootCA.txt

# Check they are a chain
# openssl verify -verbose -CAfile root_cert.pem u2f_device_cert.pem

#########################################################
#
# End verification of attestation key and certificate
#
#########################################################

echo
echo
echo "All good ?"
echo "==================================================="
echo

# If this point is reached without crashes and verification passed all is good and we have a signing 
# attestation device key and a self-signed certificate To display those in a HEX format that can be
# added to the code simply proceed and use the provided utilities e.g.:
#
# To print the attesation key in HEX, bytes, byteArray formats do
# ./print_x_y.py u2f_device_key.pem
#
# To print the device self-signed certificate in byteArray format do
# ./cbytes.py u2f_device_cert.der -s
#
# We do them here for convenience - redo at will

echo "Attestation key info in different digests"
echo "==================================================="
echo
./print_x_y.py u2f_device_key.pem

./cbytes.py u2f_device_key.der

echo "Certificate information in HEX format"
echo "==================================================="
echo
./cbytes.py u2f_device_cert.der -s

exit 0

