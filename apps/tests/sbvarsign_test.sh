#!/bin/bash
#
# Written by Stephan Mueller <smueller@chronox.de>
#
# Checker script to validate the sbvarsign tool. To utilize this script, perform
# the following steps:
#
# 1. compile leancrypto with sbvarign tool enabled
# 2. update variables LC_X509_GENERATOR, SBVARSIGN below to
#    point to the respective applications
# 3. Execute this script
#
# Expected result: no failures should be shown
#

LC_X509_GENERATOR="lc_x509_generator"
SBVARSIGN="sbvarsign"

TESTTYPE=$1

if [ -n "$2" ]
then
	LC_X509_GENERATOR=$2
fi

if [ -n "$3" ]
then
	SBVARSIGN=$3
fi

if [ ! -x "$LC_X509_GENERATOR" ]
then
	exit 77
fi

if [ ! -x "$SBVARSIGN" ]
then
	exit 77
fi

TMPDIR="./tmp.$$"

global_failure_count=0

trap "rm -rf $TMPDIR" 0 1 2 3 15
mkdir $TMPDIR

pk_file="${TMPDIR}/sbvarsign_tester_cert.der"
sk_file="${TMPDIR}/sbvarsign_tester_privkey.der"

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

check_one() {
	local inputfile=$1

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
}

lc_generate_cert_pkcs8() {
	local keytype=$1
	local pem_output=$2

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

	check_one $pk_file
}

sbvarsign_test() {
	echo_info "Leancrypto: sbvarsign create PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$SBVARSIGN \
	 --print \
	 --key ${sk_file} \
	 --cert ${pk_file} \
	 --output ${pk_file}.out \
	 -vv \
	 cert \
	 ${pk_file}

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto embedded signature generation"
	else
		echo_success "Successful leancrypto embedded signature generation"
	fi
}

################################################################################
# TEST 1
#
# Leancrypto generation of key/cert and use it for signature generation and
# verification
#
lc_sbvarsign() {
	lc_generate_cert_pkcs8 $1

	sbvarsign_test
}

################################################################################
# TEST 2
#
# Leancrypto generation of key/cert and use it for signature generation and
# verification usng PEM key/certificate format
#
lc_sbvarsign_pem() {
	lc_generate_cert_pkcs8 $1 "--pem-output"

	sbvarsign_test
}

case $TESTTYPE
in
	"ML-DSA87" | "ML-DSA-87")
		lc_sbvarsign "ML-DSA87"
		lc_sbvarsign_pem "ML-DSA87"
	;;
	"ML-DSA65" | "ML-DSA-65")
		lc_sbvarsign "ML-DSA65"
		lc_sbvarsign_pem "ML-DSA65"
	;;
	"ML-DSA44" | "ML-DSA-44")
		lc_sbvarsign "ML-DSA44"
		lc_sbvarsign_pem "ML-DSA44"
	;;
	"ML-DSA87-ED448")
		lc_sbvarsign "ML-DSA87-ED448"
		lc_sbvarsign_pem "ML-DSA87-ED448"
	;;
	"ML-DSA65-ED25519")
		lc_sbvarsign "ML-DSA65-ED25519"
		lc_sbvarsign_pem "ML-DSA65-ED25519"
	;;
	"ML-DSA44-ED25519")
		lc_sbvarsign "ML-DSA44-ED25519"
		lc_sbvarsign_pem "ML-DSA44-ED25519"
	;;
	"SLH-DSA-SHAKE-128F" | "SLH-DSA-SHAKE-128f")
		lc_sbvarsign "SLH-DSA-SHAKE-128F"
		lc_sbvarsign_pem "SLH-DSA-SHAKE-128F"
	;;
	"SLH-DSA-SHAKE-128S" | "SLH-DSA-SHAKE-128s")
		lc_sbvarsign "SLH-DSA-SHAKE-128S"
		lc_sbvarsign_pem "SLH-DSA-SHAKE-128S"
	;;
	"SLH-DSA-SHAKE-192F" | "SLH-DSA-SHAKE-192f")
		lc_sbvarsign "SLH-DSA-SHAKE-192F"
		lc_sbvarsign_pem "SLH-DSA-SHAKE-192F"
	;;
	"SLH-DSA-SHAKE-192S" | "SLH-DSA-SHAKE-192s")
		lc_sbvarsign "SLH-DSA-SHAKE-192S"
		lc_sbvarsign_pem "SLH-DSA-SHAKE-192S"
	;;
	"SLH-DSA-SHAKE-256F" | "SLH-DSA-SHAKE-256f")
		lc_sbvarsign "SLH-DSA-SHAKE-256F"
		lc_sbvarsign_pem "SLH-DSA-SHAKE-256F"
	;;
	"SLH-DSA-SHAKE-256S" | "SLH-DSA-SHAKE-256s")
		lc_sbvarsign "SLH-DSA-SHAKE-256S"
		lc_sbvarsign_pem "SLH-DSA-SHAKE-256S"
	;;
	*)
		echo_fail "Unknown test type $TESTTYPE"
	;;
esac

################################################################################
report_result
