#!/bin/bash
#
# Generate a 4-way certificate chain using leancrypto
#

TARGETDIR="$(dirname $0)"
PATHLEN=0 # Zero means unset, (> 0 - 1) -> pathlen

if [ -z "$1" ]
then
	echo "Invoke script to generate a 4-way certificate chain with one of the following options:"
	echo "  SLH-DSA"
	echo "  ML-DSA"
	echo "  Composite-ML-DSA"
	echo "  ML-DSA-passing-pathlen"
	echo "  ML-DSA-failing-pathlen"
	echo "  ML-DSA-failing-pathlen-zero"
	echo "  EDDSA"
	exit 1
fi

if [ x"$1" = x"ML-DSA" ]
then
# Full ML-DSA-based certificate chain
	CA_KEYTYPE="ML-DSA87"
	INT1_KEYTYPE="ML-DSA65"
	INT2_KEYTYPE="ML-DSA44"
	LEAF_KEYTYPE="ML-DSA87"
elif [ x"$1" = x"SLH-DSA" ]
then
	# Full SLH-DSA-based certificate chain
	CA_KEYTYPE="SLH-DSA-SHAKE-256S"
	INT1_KEYTYPE="SLH-DSA-SHAKE-256F"
	INT2_KEYTYPE="SLH-DSA-SHAKE-192F"
	LEAF_KEYTYPE="SLH-DSA-SHAKE-128F"
elif [ x"$1" = x"Composite-ML-DSA" ]
then
	# Full Composite-based certificate chain
	CA_KEYTYPE="ML-DSA87-ED448"
	INT1_KEYTYPE="ML-DSA65-ED25519"
	INT2_KEYTYPE="ML-DSA44-ED25519"
	LEAF_KEYTYPE="SLH-DSA-SHAKE-128S"
elif [ x"$1" = x"ML-DSA-passing-pathlen" ]
then
# Full ML-DSA-based certificate chain
	PATHLEN=3
	CA_KEYTYPE="ML-DSA87"
	INT1_KEYTYPE="ML-DSA65"
	INT2_KEYTYPE="ML-DSA44"
	LEAF_KEYTYPE="ML-DSA87"
elif [ x"$1" = x"ML-DSA-failing-pathlen" ]
then
# Full ML-DSA-based certificate chain
	PATHLEN=2
	CA_KEYTYPE="ML-DSA87"
	INT1_KEYTYPE="ML-DSA65"
	INT2_KEYTYPE="ML-DSA44"
	LEAF_KEYTYPE="ML-DSA87"
elif [ x"$1" = x"ML-DSA-failing-pathlen-zero" ]
then
# Full ML-DSA-based certificate chain
	PATHLEN=1
	CA_KEYTYPE="ML-DSA87"
	INT1_KEYTYPE="ML-DSA65"
	INT2_KEYTYPE="ML-DSA44"
	LEAF_KEYTYPE="ML-DSA87"

elif [ x"$1" = x"EDDSA" ]
then
# Full EdDSA-based certificate chain
	CA_KEYTYPE="Ed448"
	INT1_KEYTYPE="Ed448"
	INT2_KEYTYPE="Ed25519"
	LEAF_KEYTYPE="Ed25519"
else
	echo "Invoke script to generate a 4-way certificate chain with one of the following options:"
	echo "  SLH-DSA"
	echo "  ML-DSA"
	echo "  Composite-ML-DSA"
	echo "  ML-DSA-passing-pathlen"
	echo "  ML-DSA-failing-pathlen"
	echo "  ML-DSA-failing-pathlen-zero"
	echo "  EDDSA"
	exit 1
fi

X509_CMD="$(dirname $0)/../../../build/apps/src/lc_x509_generator"
PKCS7_CMD="$(dirname $0)/../../../build/apps/src/lc_pkcs7_generator"

################################################################################
# No further configurations below this line
################################################################################

# Generate CA certificate
# Private key in DER format and PKCS#8
CA_FILENAME="$(echo $CA_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
PATHLENCMDLINE=""
if [ $PATHLEN -gt 0 ]
then
	PATHLEN_USE=$((PATHLEN-1))
	CA_FILENAME="${CA_FILENAME}_pathlen${PATHLEN_USE}"

	PATHLENCMDLINE="--ca-pathlen $PATHLEN_USE"
fi
${X509_CMD}							\
  --keyusage digitalSignature					\
  --keyusage keyCertSign					\
  --keyusage critical						\
  --ca 								\
  $PATHLENCMDLINE						\
  --valid-from 1729527728					\
  --valid-to 2044210606						\
  --subject-cn "leancrypto test CA"				\
  --subject-ou "leancrypto test OU"				\
  --subject-o leancrypto					\
  --subject-st Saxony						\
  --subject-c DE						\
  --issuer-cn "leancrypto test CA"				\
  --issuer-ou "leancrypto test OU"				\
  --issuer-o leancrypto						\
  --issuer-st Saxony						\
  --issuer-c DE							\
  --serial 0102030405060708					\
  --skid 0a0b0c0d0e0f						\
  --akid 0a0b0c0d0e0f						\
  -o ${TARGETDIR}/${CA_FILENAME}_cacert.der			\
  --sk-file ${TARGETDIR}/${CA_FILENAME}_cacert.privkey		\
  --create-keypair-pkcs8 ${CA_KEYTYPE}				\
  --enable-non-pqc-algoritms

if [ $? -eq 0 ]
then
	echo "CA certificate generation successful"
else
	echo "CA certificate generation failed"
	exit 1
fi

# Generate Intermediate 1 certificate
# Private key in PEM format and PKCS#8
INT1_FILENAME="$(echo $INT1_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
if [ $PATHLEN -gt 0 ]
then
	PATHLEN_USE=$((PATHLEN-1))
	INT1_FILENAME="${INT1_FILENAME}_pathlen${PATHLEN_USE}"
fi
${X509_CMD}							\
  --keyusage digitalSignature					\
  --keyusage keyCertSign					\
  --keyusage critical						\
  --ca								\
  $PATHLENCMDLINE						\
  --valid-from 1729527728					\
  --valid-to 2044210606						\
  --subject-cn "leancrypto test int1"				\
  --subject-ou "leancrypto test OU"				\
  --subject-o leancrypto					\
  --subject-st Saxony						\
  --subject-c DE						\
  --serial 0203030405060708					\
  --skid 0b0c0d0e0f0001						\
  -o ${TARGETDIR}/${INT1_FILENAME}_int1.der			\
  --sk-file ${TARGETDIR}/${INT1_FILENAME}_int1.privkey		\
  --create-keypair-pkcs8 ${INT1_KEYTYPE}			\
  --pem-output							\
  --x509-signer ${TARGETDIR}/${CA_FILENAME}_cacert.der		\
  --signer-sk-file ${TARGETDIR}/${CA_FILENAME}_cacert.privkey	\
  --enable-non-pqc-algoritms

if [ $? -eq 0 ]
then
	echo "Intermediate 1 certificate generation successful"
else
	echo "Intermediate 1 certificate generation failed"
	exit 1
fi

# Generate Intermediate 2 certificate
# Private key in raw DER format
INT2_FILENAME="$(echo $INT2_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
if [ $PATHLEN -gt 0 ]
then
	PATHLEN_USE=$((PATHLEN-1))
	INT2_FILENAME="${INT2_FILENAME}_pathlen${PATHLEN_USE}"
fi
${X509_CMD}							\
  --keyusage digitalSignature					\
  --keyusage keyCertSign					\
  --keyusage critical						\
  --ca								\
  $PATHLENCMDLINE						\
  --valid-from 1729527728					\
  --valid-to 2044210606						\
  --subject-cn "leancrypto test int2"				\
  --subject-ou "leancrypto test OU"				\
  --subject-o leancrypto					\
  --subject-st Saxony						\
  --subject-c DE						\
  --serial 0303040506070809					\
  --skid 0c0d0e0f000102						\
  -o ${TARGETDIR}/${INT2_FILENAME}_int2.der			\
  --sk-file ${TARGETDIR}/${INT2_FILENAME}_int2.privkey		\
  --create-keypair-pkcs8 ${INT2_KEYTYPE}			\
  --x509-signer ${TARGETDIR}/${INT1_FILENAME}_int1.der		\
  --signer-sk-file ${TARGETDIR}/${INT1_FILENAME}_int1.privkey	\
  --enable-non-pqc-algoritms

if [ $? -eq 0 ]
then
	echo "Intermediate 2 certificate generation successful"
else
	echo "Intermediate 2 certificate generation failed"
	exit 1
fi

# Generate Leaf certificate
# Private key in raw DER format
LEAF_FILENAME="$(echo $LEAF_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
if [ $PATHLEN -gt 0 ]
then
	PATHLEN_USE=$((PATHLEN-1))
	LEAF_FILENAME="${LEAF_FILENAME}_pathlen${PATHLEN_USE}"
fi
${X509_CMD}							\
  --eku critical						\
  --eku serverAuth						\
  --eku codeSigning						\
  --keyusage dataEncipherment					\
  --valid-from 1729527728					\
  --valid-to 2044210606						\
  --san-dns "localhost"						\
  --subject-cn "localhost"					\
  --subject-ou "leancrypto test OU"				\
  --subject-o leancrypto					\
  --subject-st Saxony						\
  --subject-c DE						\
  --serial 0405060708090001					\
  --skid 0d0e0f00010203						\
  -o ${TARGETDIR}/${LEAF_FILENAME}_leaf.der			\
  --sk-file ${TARGETDIR}/${LEAF_FILENAME}_leaf.privkey		\
  --create-keypair-pkcs8 ${LEAF_KEYTYPE}			\
  --x509-signer ${TARGETDIR}/${INT2_FILENAME}_int2.der		\
  --signer-sk-file ${TARGETDIR}/${INT2_FILENAME}_int2.privkey	\
  --enable-non-pqc-algoritms

if [ $? -eq 0 ]
then
	echo "Leaf certificate generation successful"
else
	echo "Leaf certificate generation failed"
	exit 1
fi

if [ $PATHLEN -le 2 -a $PATHLEN -gt 0 ]
then
	echo "Prevent to generate the PKCS7 blob for failing path lengths"
	exit 0
fi
PKCS7_FILENAME="$(echo $1 | tr '[:upper:]' '[:lower:]' )"
if [ $PATHLEN -gt 0 ]
then
	PATHLEN_USE=$((PATHLEN-1))
	PKCS7_FILENAME="${PKCS7_FILENAME}_pathlen${PATHLEN_USE}"
fi
${PKCS7_CMD}							\
  --print							\
  -o ${TARGETDIR}/${PKCS7_FILENAME}.p7b				\
  -i ${TARGETDIR}/${CA_FILENAME}_cacert.der			\
  --x509-signer ${TARGETDIR}/${LEAF_FILENAME}_leaf.der		\
  --signer-sk-file ${TARGETDIR}/${LEAF_FILENAME}_leaf.privkey	\
  --x509-cert ${TARGETDIR}/${INT2_FILENAME}_int2.der		\
  --x509-cert ${TARGETDIR}/${INT1_FILENAME}_int1.der		\
  --x509-cert ${TARGETDIR}/${CA_FILENAME}_cacert.der		\
  --trust-anchor ${TARGETDIR}/${CA_FILENAME}_cacert.der		\
  --enable-non-pqc-algoritms
