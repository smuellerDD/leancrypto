#!/bin/bash
#
# Written by Stephan Mueller <smueller@chronox.de>
#
# Checker script to validate the X.509 certificates along with private keys
# can create signatures that can be validated with OpenSSL and vice versa.
#
# To utilize this script, perform the following steps:
#
# 1. compile leancrypto with X.509 generator enabled
# 2. update variable LC_X509_GENERATOR below to point to the lc_x509_generator
#    tool
# 3. Execute this script
#
# Expected result: no failures should be shown
#

LC_X509_GENERATOR="lc_x509_generator"
LC_PKCS7_GENERATOR="lc_pkcs7_generator"
OPENSSL="/usr/bin/openssl"

TESTTYPE=$1


if [ -n "$2" ]
then
	LC_X509_GENERATOR=$2
fi

if [ -n "$3" ]
then
	LC_PKCS7_GENERATOR=$3
fi

if [ -n "$4" ]
then
	OPENSSL=$4
fi

if [ ! -x "$LC_X509_GENERATOR" ]
then
	exit 77
fi

if [ ! -x "$LC_PKCS7_GENERATOR" ]
then
	exit 77
fi

if [ ! -x "$OPENSSL" ]
then
	exit 77
fi

# We need OpenSSL version 3.5.2 as a minimum
opensslver=$($OPENSSL --version | cut -f 2 -d" ")
if [ -z "$opensslver" ]
then
	exit 77
fi
openssl_ver_may=$(echo $opensslver | cut -f1 -d ".")
openssl_ver_min=$(echo $opensslver | cut -f2 -d ".")
openssl_ver_patch=$(echo $opensslver | cut -f3 -d ".")
if [ "$openssl_ver_may" -lt "3" ]
then
	exit 77
fi

if [ "$openssl_ver_may" -eq "3" -a "$openssl_ver_min" -lt "5" ]
then
	exit 77
fi

if [ "$openssl_ver_may" -eq "3" -a "$openssl_ver_min" -eq "5"  -a "$openssl_ver_patch" -lt "2" ]
then
	exit 77
fi

TMPDIR="./tmp.$$"

global_failure_count=0

trap "rm -rf $TMPDIR" 0 1 2 3 15
mkdir $TMPDIR

pk_file="${TMPDIR}/siggen_tester_cert.der"
sk_file="${TMPDIR}/siggen_tester_privkey.der"

color()
{
	bg=0
	echo -ne "\033[0m"
	while [[ $# -gt 0 ]]; do
		code=0
		case $1 in
			black) code=30 ;;
			red) code=31 ;;
			green) code=32 ;;
			yellow) code=33 ;;
			blue) code=34 ;;
			magenta) code=35 ;;
			cyan) code=36 ;;
			white) code=37 ;;
			background|bg) bg=10 ;;
			foreground|fg) bg=0 ;;
			reset|off|default) code=0 ;;
			bold|bright) code=1 ;;
		esac
		[[ $code == 0 ]] || echo -ne "\033[$(printf "%02d" $((code+bg)))m"
		shift
	done
}

echo_success()
{
	echo $(color "green")[SUCCESS]$(color off) "$@"
}

echo_fail()
{
	echo $(color "red")[FAILURE]$(color off) "$@"
	global_failure_count=$(($global_failure_count+1))
}

echo_info()
{
	echo $(color "magenta")[INFO]$(color off) "$@"
}

check_one() {
	local inputfile=$1
	local inform=$2

	if [ ! -f "$inputfile" ]
	then
		echo_fail "Cannot find $inputfile"
		exit 1
	fi

	echo "=== Checking file $inputfile with Leancrypto ==="
	$LC_X509_GENERATOR --check-selfsigned --print-x509 $inputfile
	if [ $? -ne 0 ]
	then
		echo_fail "Parsing of file $inputfile was unsuccessful"
	else
		echo_success "Parsing of file $inputfile was successful"
	fi

	echo "=== Checking file $inputfile with OpenSSL ==="
	$OPENSSL x509 -in $inputfile -inform $inform -text -noout
	if [ $? -ne 0 ]
	then
		echo_fail "Parsing of file $inputfile was unsuccessful"
	else
		echo_success "Parsing of file $inputfile was successful"
	fi

	if [ "x$inform" = "xPEM" ]
	then
		# Check DOS-Variant as well
		echo "=== Checking DOS-variant of file $inputfile with Leancrypto ==="
		sed -i 's/$/\r/' $inputfile
		$LC_X509_GENERATOR --check-selfsigned --print-x509 $inputfile
		if [ $? -ne 0 ]
		then
			echo_fail "Parsing of file $inputfile was unsuccessful"
		else
			echo_success "Parsing of file $inputfile was successful"
		fi
	fi
}

check_one_priv() {
	local inputfile=$1
	local inform=$2

	if [ ! -f "$inputfile" ]
	then
		echo_fail "Cannot find $inputfile"
		exit 1
	fi

	echo "=== Checking private key file $inputfile with OpenSSL ==="
	$OPENSSL asn1parse -dump -in $inputfile -inform $inform
	if [ $? -ne 0 ]
	then
		echo_fail "Parsing of file $inputfile was unsuccessful"
	else
		echo_success "Parsing of file $inputfile was successful"
	fi
}

report_result() {
	echo "=== Final Result ==="
	if [ $global_failure_count -eq 0 ]
	then
		echo_success "No failures"
		exit 0
	else
		echo_fail "Total number of failures: $global_failure_count"
		exit 1
	fi
}

lc_generate_cert_pkcs8() {
	local keytype=$1
	local inform=$2
	local pem_output=$3

	rm -f ${pk_file} ${sk_file}

	echo_info "Leancrypto: Generate X.509 certificate and associated PKCS#8 private key"

	$LC_X509_GENERATOR \
	 $pem_output \
	 --keyusage digitalSignature \
	 --keyusage keyEncipherment \
	 --keyusage keyCertSign \
	 --keyusage critical \
	 --ca \
	 --valid-days 365 \
	 --subject-cn 'leancrypto test CA' \
	 --create-keypair-pkcs8 $keytype \
	 --sk-file $sk_file \
	 --outfile $pk_file

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto-internal certificate / PKCS#8 key generation"
	else
		echo_success "Successful leancrypto-internal certificate / PKCS#8 key generation"
	fi

	check_one $pk_file $inform
	check_one_priv $sk_file $inform
}

lc_generate_cert_pkcs8_seed() {
	local keytype=$1
	local inform=$2
	local pem_output=$3

	rm -f ${pk_file} ${sk_file}

	echo_info "Leancrypto: Generate X.509 certificate and associated PKCS#8 private key"

	$LC_X509_GENERATOR \
	 $pem_output \
	 --keyusage digitalSignature \
	 --keyusage keyEncipherment \
	 --keyusage keyCertSign \
	 --keyusage critical \
	 --ca \
	 --valid-days 365 \
	 --subject-cn 'leancrypto test CA' \
	 --create-keypair-pkcs8-seed $keytype \
	 --sk-file $sk_file \
	 --outfile $pk_file

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto-internal certificate / PKCS#8 key generation"
	else
		echo_success "Successful leancrypto-internal certificate / PKCS#8 key generation"
	fi

	check_one $pk_file $inform
	check_one_priv $sk_file $inform

	local sk_size=""

	if [ "$(uname -s)" = "Darwin" ]
	then
		sk_size=$(stat -f "%z" $sk_file)
	else
		sk_size=$(stat --printf="%s" $sk_file)
	fi

	# Use 170 to cover the largest seed keys of SLH-DSA
	if [ $sk_size -lt 170 ]
	then
		echo_success "PKCS#8 with seed key generated"
	else
		echo_fail "PKCS#8 does not seem to be a seed key"
	fi
}

lc_sign_cert() {
	local pem_output=$1

	rm -f ${pk_file}.p7b

	echo_info "Leancrypto: Create PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$LC_PKCS7_GENERATOR \
	 --md SHA2-512 \
	 $pem_output \
	 -i ${pk_file} \
	 -o ${pk_file}.p7b \
	 --x509-signer  ${pk_file} \
	 --signer-sk-file ${sk_file} \
	 --print

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto signature generation"
	else
		echo_success "Successful leancrypto signature generation"
	fi
}

lc_verify_cert() {
	echo_info "Leancrypto: Verify PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$LC_PKCS7_GENERATOR \
	 --print-pkcs7 ${pk_file}.p7b \
	 -i ${pk_file} \
	 --trust-anchor ${pk_file}

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto signature verification"
	else
		echo_success "Successful leancrypto signature verification"
	fi
}

ossl_generate_cert_pkcs8() {
	local keytype=$1
	local inform=$2

	rm -f ${pk_file} ${sk_file}

	echo_info "OpenSSL Generate X.509 certificate and associated PKCS#8 private key"

	$OPENSSL genpkey -algorithm $keytype -out $sk_file -outform $inform
	$OPENSSL pkey -in $sk_file -inform $inform -pubout -out $pk_file.raw.pem
	$OPENSSL req \
	 -new \
	 -x509 \
	 -key $sk_file \
	 -out $pk_file \
	 -outform $inform \
	 -subj "/CN=OpenSSL test CA" \
	 -addext basicConstraints=critical,CA:TRUE \
	 -addext keyUsage=critical,digitalSignature,cRLSign,keyCertSign

	if [ $? -ne 0 ]
	then
		echo_fail "Failed OpenSSL certificate / PKCS#8 key generation"
	else
		echo_success "Successful OpenSSL certificate / PKCS#8 key generation"
	fi

	check_one $pk_file $inform
	check_one_priv $sk_file $inform
}

ossl_sign_cert() {
	rm -f ${pk_file}.p7b

	echo_info "OpenSSL: Create PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$OPENSSL cms \
	 -binary \
	 -nosmimecap \
	 -sign \
	 -outform DER \
	 -in ${pk_file} \
	 -out ${pk_file}.p7b \
	 -signer ${pk_file} \
	 -inkey ${sk_file} \
	 -md SHA512

	if [ $? -ne 0 ]
	then
		echo_fail "Failed openssl signature generation"
	else
		echo_success "Successful leancrypto-internal signature generation"
	fi
}

ossl_verify_cert() {
	echo_info "OpenSSL: Verify PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$OPENSSL cms \
	 -verify \
	 -binary \
	 -in ${pk_file}.p7b \
	 -CAfile ${pk_file} \
	 -content ${pk_file} \
	 -inform DER >/dev/null

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto-internal signature verification"
	else
		echo_success "Successful leancrypto-internal signature verification"
	fi
}

################################################################################
# TEST 1
#
# Leancrypto generation of key/cert and use it for signature generation and
# verification
#
lc_keygen_lc_op() {
	lc_generate_cert_pkcs8 $1 "DER"

	lc_sign_cert
	lc_verify_cert

	ossl_sign_cert
	lc_verify_cert

	lc_sign_cert
	ossl_verify_cert
}

################################################################################
# TEST 2
#
# OpenSSL generation of key/cert and use it for signature generation and
# verification
#
ossl_keygen_lc_op() {
	ossl_generate_cert_pkcs8 $1 "DER"

	lc_sign_cert
	lc_verify_cert

	ossl_sign_cert
	lc_verify_cert

	lc_sign_cert
	ossl_verify_cert
}

################################################################################
# TEST 3
#
# Leancrypto seed key generation of key/cert and use it for signature generation
# and verification
#
# NOTE: SLH-DSA out of the box generates keys where the PK and SK are seeds.
# Thus, the key type generated by ossl_generate_cert_pkcs8 and
# lc_generate_cert_pkcs8_seed is identical. Yet, we test SLH-DSA here for
# completeness reasons to ensure that the different API calls work with
# SLH-DSA as well.
#
# NOTE OpenSSL does not support reading PKCS#8 blobs with seed keys, thus
# only perform sigver with OpenSSL
#
lc_keygen_seed_lc_op() {
	lc_generate_cert_pkcs8_seed $1 "DER"

	lc_sign_cert
	lc_verify_cert

	lc_sign_cert
	ossl_verify_cert
}

################################################################################
# TEST 4
#
# Leancrypto generation of key/cert and use it for signature generation and
# verification
#
lc_keygen_lc_op_pem() {
	lc_generate_cert_pkcs8 $1 "PEM" "--pem-output"

	lc_sign_cert "--pem-output"
	lc_verify_cert
}

################################################################################
# TEST 5
#
# OpenSSL generation of key/cert and use it for signature generation and
# verification
#
ossl_keygen_lc_op_pem() {
	ossl_generate_cert_pkcs8 $1 "PEM"

	lc_sign_cert "--pem-output"
	lc_verify_cert
}

case $TESTTYPE
in
	"ML-DSA87" | "ML-DSA-87")
		lc_keygen_lc_op "ML-DSA87"
		ossl_keygen_lc_op "ML-DSA-87"
		lc_keygen_seed_lc_op "ML-DSA87"
		lc_keygen_lc_op_pem "ML-DSA87"
		ossl_keygen_lc_op_pem "ML-DSA-87"
	;;
	"ML-DSA65" | "ML-DSA-65")
		lc_keygen_lc_op "ML-DSA65"
		ossl_keygen_lc_op "ML-DSA-65"
		lc_keygen_seed_lc_op "ML-DSA65"
		lc_keygen_lc_op_pem "ML-DSA65"
		ossl_keygen_lc_op "ML-DSA-65"
	;;
	"ML-DSA44" | "ML-DSA-44")
		lc_keygen_lc_op "ML-DSA44"
		ossl_keygen_lc_op "ML-DSA-44"
		lc_keygen_seed_lc_op "ML-DSA44"
		lc_keygen_lc_op_pem "ML-DSA44"
		ossl_keygen_lc_op_pem "ML-DSA-44"
	;;
	"SLH-DSA-SHAKE-128F" | "SLH-DSA-SHAKE-128f")
		lc_keygen_lc_op "SLH-DSA-SHAKE-128F"
		ossl_keygen_lc_op "SLH-DSA-SHAKE-128f"
		lc_keygen_seed_lc_op "SLH-DSA-SHAKE-128F"
		lc_keygen_lc_op_pem "SLH-DSA-SHAKE-128F"
		ossl_keygen_lc_op_pem "SLH-DSA-SHAKE-128f"
	;;
	"SLH-DSA-SHAKE-128S" | "SLH-DSA-SHAKE-128s")
		lc_keygen_lc_op "SLH-DSA-SHAKE-128S"
		ossl_keygen_lc_op "SLH-DSA-SHAKE-128s"
		lc_keygen_seed_lc_op "SLH-DSA-SHAKE-128S"
		lc_keygen_lc_op_pem "SLH-DSA-SHAKE-128S"
		ossl_keygen_lc_op_pem "SLH-DSA-SHAKE-128s"
	;;
	"SLH-DSA-SHAKE-192F" | "SLH-DSA-SHAKE-192f")
		lc_keygen_lc_op "SLH-DSA-SHAKE-192F"
		ossl_keygen_lc_op "SLH-DSA-SHAKE-192f"
		lc_keygen_seed_lc_op "SLH-DSA-SHAKE-192F"
		lc_keygen_lc_op_pem "SLH-DSA-SHAKE-192F"
		ossl_keygen_lc_op_pem "SLH-DSA-SHAKE-192f"
	;;
	"SLH-DSA-SHAKE-192S" | "SLH-DSA-SHAKE-192s")
		lc_keygen_lc_op "SLH-DSA-SHAKE-192S"
		ossl_keygen_lc_op "SLH-DSA-SHAKE-192s"
		lc_keygen_seed_lc_op "SLH-DSA-SHAKE-192S"
		lc_keygen_lc_op_pem "SLH-DSA-SHAKE-192S"
		ossl_keygen_lc_op_pem "SLH-DSA-SHAKE-192s"
	;;
	"SLH-DSA-SHAKE-256F" | "SLH-DSA-SHAKE-256f")
		lc_keygen_lc_op "SLH-DSA-SHAKE-256F"
		ossl_keygen_lc_op "SLH-DSA-SHAKE-256f"
		lc_keygen_seed_lc_op "SLH-DSA-SHAKE-256F"
		lc_keygen_lc_op_pem "SLH-DSA-SHAKE-256F"
		ossl_keygen_lc_op_pem "SLH-DSA-SHAKE-256f"
	;;
	"SLH-DSA-SHAKE-256S" | "SLH-DSA-SHAKE-256s")
		lc_keygen_lc_op "SLH-DSA-SHAKE-256S"
		ossl_keygen_lc_op "SLH-DSA-SHAKE-256s"
		lc_keygen_seed_lc_op "SLH-DSA-SHAKE-256S"
		lc_keygen_lc_op_pem "SLH-DSA-SHAKE-256S"
		ossl_keygen_lc_op_pem "SLH-DSA-SHAKE-256s"
	;;
	*)
		echo_fail "Unknown test type $TESTTYPE"
	;;
esac

################################################################################
report_result
