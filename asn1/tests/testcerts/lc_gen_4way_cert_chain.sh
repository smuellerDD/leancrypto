#!/bin/bash
#
# Generate a 4-way certificate chain using leancrypto
#

TARGETDIR="$(dirname $0)"

if [ -z "$1" ]
then
	echo "Invoke script to generate a 4-way certificate chain with one of the following options:"
	echo "  SLH-DSA"
	echo "  ML-DSA"
	echo "  Composite-ML-DSA"
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
	# Full SLH-DSA-based certificate chain
	CA_KEYTYPE="ML-DSA65-ED25519"
	INT1_KEYTYPE="ML-DSA44-ED25519"
	INT2_KEYTYPE="ML-DSA87"
	LEAF_KEYTYPE="SLH-DSA-SHAKE-128S"
else
	echo "Invoke script to generate a 4-way certificate chain with one of the following options:"
	echo "  SLH-DSA"
	echo "  ML-DSA"
	echo "  Composite-ML-DSA"
	exit 1
fi

X509_CMD="$(dirname $0)/../../../build/apps/src/lc_x509_generator"
PKCS7_CMD="$(dirname $0)/../../../build/apps/src/lc_pkcs7_generator"

################################################################################
# No further configurations below this line
################################################################################

# Generate CA certificate
CA_FILENAME="$(echo $CA_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
${X509_CMD}							\
  --keyusage digitalSignature					\
  --keyusage keyEncipherment					\
  --keyusage keyCertSign					\
  --keyusage critical						\
  --ca 								\
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
  --create-keypair ${CA_KEYTYPE}

if [ $? -eq 0 ]
then
	echo "CA certificate generation successful"
else
	echo "CA certificate generation failed"
	exit 1
fi

# Generate Intermediate 1 certificate
INT1_FILENAME="$(echo $INT1_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
${X509_CMD}							\
  --keyusage digitalSignature					\
  --keyusage keyEncipherment					\
  --keyusage keyCertSign					\
  --keyusage critical						\
  --ca								\
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
  --create-keypair ${INT1_KEYTYPE}				\
  --x509-signer ${TARGETDIR}/${CA_FILENAME}_cacert.der		\
  --signer-sk-file ${TARGETDIR}/${CA_FILENAME}_cacert.privkey

if [ $? -eq 0 ]
then
	echo "Intermediate 1 certificate generation successful"
else
	echo "Intermediate 1 certificate generation failed"
	exit 1
fi

# Generate Intermediate 2 certificate
INT2_FILENAME="$(echo $INT2_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
${X509_CMD}							\
  --keyusage digitalSignature					\
  --keyusage keyEncipherment					\
  --keyusage keyCertSign					\
  --keyusage critical						\
  --ca								\
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
  --create-keypair ${INT2_KEYTYPE}				\
  --x509-signer ${TARGETDIR}/${INT1_FILENAME}_int1.der		\
  --signer-sk-file ${TARGETDIR}/${INT1_FILENAME}_int1.privkey

if [ $? -eq 0 ]
then
	echo "Intermediate 2 certificate generation successful"
else
	echo "Intermediate 2 certificate generation failed"
	exit 1
fi

# Generate Leaf certificate
LEAF_FILENAME="$(echo $LEAF_KEYTYPE | tr '[:upper:]' '[:lower:]' )"
${X509_CMD}							\
  --keyusage dataEncipherment					\
  --keyusage critical						\
  --eku critical						\
  --eku serverAuth						\
  --eku codeSigning						\
  --valid-from 1729527728					\
  --valid-to 2044210606						\
  --subject-cn "leancrypto test leaf"				\
  --subject-ou "leancrypto test OU"				\
  --subject-o leancrypto					\
  --subject-st Saxony						\
  --subject-c DE						\
  --serial 0405060708090001					\
  --skid 0d0e0f00010203						\
  -o ${TARGETDIR}/${LEAF_FILENAME}_leaf.der			\
  --sk-file ${TARGETDIR}/${LEAF_FILENAME}_leaf.privkey		\
  --create-keypair ${LEAF_KEYTYPE}				\
  --x509-signer ${TARGETDIR}/${INT2_FILENAME}_int2.der		\
  --signer-sk-file ${TARGETDIR}/${INT2_FILENAME}_int2.privkey

if [ $? -eq 0 ]
then
	echo "Leaf certificate generation successful"
else
	echo "Leaf certificate generation failed"
	exit 1
fi

PKCS7_FILENAME="$(echo $1 | tr '[:upper:]' '[:lower:]' )"
${PKCS7_CMD}							\
  --print							\
  -o ${TARGETDIR}/${PKCS7_FILENAME}.p7b				\
  -i ${TARGETDIR}/${CA_FILENAME}_cacert.der			\
  --x509-signer ${TARGETDIR}/${LEAF_FILENAME}_leaf.der		\
  --signer-sk-file ${TARGETDIR}/${LEAF_FILENAME}_leaf.privkey	\
  --x509-cert ${TARGETDIR}/${INT2_FILENAME}_int2.der		\
  --x509-cert ${TARGETDIR}/${INT1_FILENAME}_int1.der		\
  --x509-cert ${TARGETDIR}/${CA_FILENAME}_cacert.der		\
  --trust-anchor ${TARGETDIR}/${CA_FILENAME}_cacert.der
