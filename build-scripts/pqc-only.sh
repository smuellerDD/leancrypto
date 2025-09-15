#!/bin/bash

#
# This script defines the option set required for building leancrypto to only
# offer PQC.
#
# The following support is enabled with C and accelerated implementations:
#
# - SHA-3 support providing the primitives to ML-KEM
# - ML-KEM along with its composite algorithms (IES support disabled due to
#   disabled AEAD support)
# - ML-DSA along with its composite algorithms
# - SLH-DSA
# - SHAKE SIMD support, if applicable
# - FIPS 140 integrity checker for ELF
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
 -Daes_xts=disabled
 -Dchacha20=disabled
"

DISABLE_HASH="
 -Dsha2-256=disabled
"

DISABLE_SIGNATURE="
 -Dslh_dsa_ascon_128s=disabled
 -Dslh_dsa_ascon_128f=disabled
"

DISABLE_KEM="
 -Dbike_5=disabled
 -Dbike_3=disabled
 -Dbike_1=disabled
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
 -Dx509_parser=disabled
 -Dpkcs7_parser=disabled
"

DISABLE_MISC="
 -Dhmac=disabled
 -Dhotp=disabled
 -Dtotp=disabled
 -Dapps=disabled
"

FORCE_SEEDSOURCE="
"

meson setup build-pqc-only \
 $DISABLE_AEAD \
 $DISABLE_SYM \
 $DISABLE_HASH \
 $DISABLE_SIGNATURE \
 $DISABLE_KEM \
 $DISABLE_DRNG \
 $DISABLE_KDF \
 $DISABLE_ASN1 \
 $DISABLE_MISC \
 $FORCE_SEEDSOURCE

