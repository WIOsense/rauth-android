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
# unit="Root CA"
CN="wiosense.de"

# # Generate the EC private key using a good source of randomness (preferably a TRNG) -> generate trngseed.bin at your own will
# # The utility script to generate such a secret on UNIX kernels is generateCryptoRandomSeed returning a 256bit entropy seed
# openssl ecparam -genkey -name "$curve" -out root_key.pem -rand trngseed.bin

# # Generate a "signing request"
# openssl req -new -key root_key.pem -out root_key.pem.csr -subj "/C=$country/O=$organization/OU=$unit/CN=$CN"

# # Self sign the request
# openssl x509 -trustout -req -days 3652  -in root_key.pem.csr -signkey root_key.pem -out root_cert.pem -sha256

# # Convert to smaller size format DER
# openssl  x509 -in root_cert.pem -outform der -out root_cert.der

# # Print out information and verify
# openssl x509 -in root_cert.pem -text -noout

# echo "==================================================="
# echo

#########################################################
#
# End root of trust self-signed key pair as the Root CA
#
#########################################################

#########################################################
#
# Begin attestation certificate key pair to go on device
#
#########################################################

# You need to create a extended certificate for the device certificate to work with FIDO2. 
# You need to create this file, v3.ext, and add these options to it.
# subjectKeyIdentifier=hash
# authorityKeyIdentifier=keyid,issuer
# basicConstraints=CA:FALSE
# keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment

echo "Device signing key and attestation certificate"
echo "==================================================="
echo

unit="Authenticator Attestation"    # MUST KEEP THIS AS "Authenticator Attestation" for FIDO2.

# Generate EC private key 
openssl ecparam -genkey -name "$curve" -out device_key.pem -rand trngseed.bin

# Generate the EC private key also in PKCS8 format
openssl pkcs8 -topk8 -nocrypt -in device_key.pem -out device_key_pkcs8.pem

# Generate the EC private key also in DER format for handling in HEX 
openssl ec -in device_key_pkcs8.pem -outform DER -out device_key.der

# Generate a "signing request" - note for Full Basic Attestation including CA Certs one must self-sign with Root CA
# as for instance below
# openssl x509 -req -days 3652  -in u2f_device_key.pem.csr -extfile u2f_v3.ext -CA root_cert.pem -CAkey root_key.pem -set_serial 01 -out u2f_device_cert.pem -sha256
# Here however we go ahead with single self-signed certificate
openssl req -new -key device_key_pkcs8.pem -out device_key.pem.csr -subj "/C=$country/O=$organization/OU=$unit/CN=$CN"

# Self-sign the request - is sufficient for Basic Attestation format - there is limited support for CA root
openssl x509 -req -days 3652 -in device_key.pem.csr -extfile v3.ext -signkey device_key.pem -out device_cert.pem -sha256

# Convert to smaller size format DER
openssl x509 -in device_cert.pem  -outform der -out device_cert.der

# Verify the device certificate details
openssl x509 -in device_cert.pem -text -noout

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
openssl dgst -sha256 -sign device_key_pkcs8.pem -out sig.txt chal.txt
openssl dgst -sha256 -verify  <(openssl x509 -in device_cert.pem  -pubkey -noout)  -signature sig.txt chal.txt

# openssl dgst -sha256 -sign root_key.pem -out sig_rootCA.txt chal_rootCA.txt
# openssl dgst -sha256 -verify  <(openssl x509 -in root_cert.pem  -pubkey -noout)  -signature sig_rootCA.txt chal_rootCA.txt

# Check they are a chain
# openssl verify -verbose -CAfile root_cert.pem device_cert.pem

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
# ./print_x_y.py device_key.pem
#
# To print the device self-signed certificate in byteArray format do
# ./cbytes.py device_cert.der -s
#
# We do them here for convenience - redo at will

echo "Attestation key info in different digests"
echo "==================================================="
echo
./print_x_y.py device_key.pem

./cbytes.py device_key.der

echo "Certificate information in HEX format"
echo "==================================================="
echo
./cbytes.py device_cert.der -s

exit 0

