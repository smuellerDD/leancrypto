#!/bin/bash

#
# This script defines the option set required for building leancrypto to work
# for the Shim boot loader.
#
# The resulting leancrypto has the following properties
#
# * built for EFI environment
# * all enabled ciphers are compiled with full acceleration
# * disable all cryptography except:
#   - SHA2-256
#   - SHA2-512
#   - ML-DSA (all key sizes)
#   - SLH-DSA (all sizes)
#   - Composite ML-DSA and ED25519
#   - Composite ML-DSA and ED448
#   - X.509 parser
#   - PKCS7 parser
#

DISABLE_AEAD="
 -Dascon=disabled
 -Dascon_keccak=disabled
 -Daes_gcm=disabled
 -Dchacha20poly1305=disabled
 -Dhash_crypt=disabled
"

DISABLE_SYM="
 -Daes_block=disabled
 -Daes_cbc=disabled
 -Daes_ctr=disabled
 -Daes_kw=disabled
 -Dchacha20=disabled
"

DISABLE_SIGNATURE="
 -Dslh_dsa_ascon_128s=disabled
 -Dslh_dsa_ascon_128f=disabled
"

DISABLE_KEM="
 -Dbike_5=disabled
 -Dbike_3=disabled
 -Dbike_1=disabled
 -Dkyber_1024=disabled
 -Dkyber_768=disabled
 -Dkyber_512=disabled
 -Dkyber_x25519=disabled
 -Dkyber_x448=disabled
 -Dhqc_256=disabled
 -Dhqc_192=disabled
 -Dhqc_128=disabled
"

DISABLE_DRNG="
 -Dchacha20_drng=disabled
 -Ddrbg_hash=disabled
 -Ddrbg_hmac=disabled
 -Dkmac_drng=disabled
 -Dcshake_drng=disabled
"

DISABLE_KDF="
 -Dhkdf=disabled
 -Dkdf_ctr=disabled
 -Dkdf_fb=disabled
 -Dkdf_dpi=disabled
 -Dpbkdf2=disabled
"

DISABLE_ASN1="
 -Dx509_generator=disabled
 -Dpkcs7_generator=disabled
"

DISABLE_MISC="
 -Dhmac=disabled
 -Dkmac=disabled
 -Dhotp=disabled
 -Dtotp=disabled
 -Dapps=disabled
"

FORCE_SEEDSOURCE="
 -Dseedsource=cpu
"

# Optionally disable unused signatures
# -Dsphincs_shake_256s=disabled -Dsphincs_shake_256f=disabled
# -Dsphincs_shake_192s=disabled -Dsphincs_shake_192f=disabled
# -Dsphincs_shake_128s=disabled -Dsphincs_shake_128f=disabled
# -Ddilithium_ed25519=disabled -Ddilithium_ed448=disabled
# -Ddilithium_87=disabled -Ddilithium_65=disabled -Ddilithium_44=disabled

meson setup build-shim \
 -Defi=enabled \
 $DISABLE_AEAD \
 $DISABLE_SYM \
 $DISABLE_SIGNATURE \
 $DISABLE_KEM \
 $DISABLE_DRNG \
 $DISABLE_KDF \
 $DISABLE_ASN1 \
 $DISABLE_MISC \
 $FORCE_SEEDSOURCE

