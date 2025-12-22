#!/bin/bash

#
# This script defines the option set required for building leancrypto to only
# offer AES-GCM
#
# The following support is enabled with C and accelerated implementations:
#
# - SHA-3 support to provide primitives to XDRBG
# - XDRBG / seeded RNG to provide entropy to internal GCM IV generation
# - AES-GCM
# - FIPS 140 integrity checker for ELF
#

DISABLE_AEAD="
 -Dascon=disabled
 -Dascon_keccak=disabled
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
 -Dsha2-512=disabled
"

DISABLE_SIGNATURE="
 -Dslh_dsa_ascon_128s=disabled
 -Dslh_dsa_ascon_128f=disabled
 -Dsphincs_shake_256s=disabled
 -Dsphincs_shake_256f=disabled
 -Dsphincs_shake_192s=disabled
 -Dsphincs_shake_192f=disabled
 -Dsphincs_shake_128s=disabled
 -Dsphincs_shake_128f=disabled
 -Ddilithium_ed25519=disabled
 -Ddilithium_ed448=disabled
 -Ddilithium_87=disabled
 -Ddilithium_65=disabled
 -Ddilithium_44=disabled
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
 -Ddrbg_ctr=disabled
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
 -Dpkcs8_generator=disabled
 -Dx509_parser=disabled
 -Dpkcs7_parser=disabled
 -Dpkcs8_parser=disabled
"

DISABLE_MISC="
 -Dhmac=disabled
 -Dkmac=disabled
 -Dhotp=disabled
 -Dtotp=disabled
 -Dapps=disabled
"

FORCE_SEEDSOURCE="
"

meson setup build-aesgcm-only \
 $DISABLE_AEAD \
 $DISABLE_SYM \
 $DISABLE_HASH \
 $DISABLE_SIGNATURE \
 $DISABLE_KEM \
 $DISABLE_DRNG \
 $DISABLE_KDF \
 $DISABLE_ASN1 \
 $DISABLE_MISC \
 $FORCE_SEEDSOURCE $@

