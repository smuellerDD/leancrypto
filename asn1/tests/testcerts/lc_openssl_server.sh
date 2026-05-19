#!/bin/bash

PORT=$1
DIR=$2

if [ -z "$PORT" ]
then
	PORT=9999
fi

openssl							\
  s_server						\
  -naccept 1						\
  -port $PORT						\
  -cert ${DIR}ed25519_leaf.der				\
  -certform DER						\
  -key ${DIR}ed25519_leaf.privkey			\
  -keyform DER						\
  -state -www						\
  -no_cache -tls1_3					\
  -ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256 \
  -groups X25519:MLKEM768:MLKEM1024:X25519MLKEM768
