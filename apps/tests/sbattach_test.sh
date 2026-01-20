#!/bin/bash
#
# Written by Stephan Mueller <smueller@chronox.de>
#
# Checker script to validate the sbsign tool. To utilize this script, perform
# the following steps:
#
# 1. compile leancrypto with sbign tool enabled
# 2. update variables LC_X509_GENERATOR, SBSIGN, LC_PKCS7_GENERATOR below to
#    point to the respective applications
# 3. Execute this script
#
# Expected result: no failures should be shown
#

LC_X509_GENERATOR="lc_x509_generator"
SBSIGN="sbsign"
SBATTACH="sbattach"
EFIFILE=""

TESTTYPE=$1

if [ -n "$2" ]
then
	LC_X509_GENERATOR=$2
fi

if [ -n "$3" ]
then
	SBSIGN=$3
fi

if [ -n "$4" ]
then
	SBATTACH=$4
fi

if [ -n "$5" ]
then
	EFIFILE=$5
fi

if [ ! -x "$LC_X509_GENERATOR" ]
then
	exit 77
fi

if [ ! -x "$SBSIGN" ]
then
	exit 77
fi

if [ ! -x "$SBATTACH" ]
then
	exit 77
fi

if [ ! -x "$EFIFILE" ]
then
	exit 77
fi

TMPDIR="./tmp.$$"

global_failure_count=0

trap "rm -rf $TMPDIR" 0 1 2 3 15
mkdir $TMPDIR

pk_file="${TMPDIR}/sbsign_tester_cert.der"
sk_file="${TMPDIR}/sbsign_tester_privkey.der"

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

sbsign_cert() {
	local output="$TMPDIR/$(basename $EFIFILE).signed"
	local output2="$TMPDIR/$(basename $EFIFILE).signed2"

	rm -f $output $output2

	echo_info "Leancrypto: sbsign create PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$SBSIGN \
	 --key ${sk_file} \
	 --cert ${pk_file} \
	 --output $output \
	 --print \
	 $EFIFILE

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto embedded signature generation"
	else
		echo_success "Successful leancrypto embedded signature generation"
	fi

	# Create file with 2 signatures
	$SBSIGN \
	 --key ${sk_file} \
	 --cert ${pk_file} \
	 --output $output2 \
	 $output

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto dual embedded signature generation"
	else
		echo_success "Successful leancrypto dual embedded signature generation"
	fi
}

sbsign_cert_detached() {
	local output="$TMPDIR/$(basename $EFIFILE).pk7"

	rm -f $output

	echo_info "Leancrypto: sbsign create detached PKCS#7 signature of PE/COFF file using the X.509 certificate and associated PKCS#8 private key as signer"

	$SBSIGN \
	 --detached \
	 --key ${sk_file} \
	 --cert ${pk_file} \
	 --output $output \
	 $EFIFILE

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto detached signature generation"
	else
		echo_success "Successful leancrypto detached signature generation"
	fi
}

sbdetach_cert() {
	local output="$TMPDIR/$(basename $EFIFILE).signed"
	local output2="$TMPDIR/$(basename $EFIFILE).signed2"
	local output_sig="$TMPDIR/$(basename $EFIFILE).sig"
	local output_reattach="$TMPDIR/$(basename $EFIFILE).reattach"

	echo_info "Leancrypto: sbattach PKCS#7 signature of PE/COFF file using the X.509 certificate and associated PKCS#8 private key as signer"

	cp -f $output $output_reattach

	$SBATTACH \
	 --detach ${output_sig} \
	 --remove \
	 $output_reattach

	if [ $? -ne 0 ]
	then
		echo_fail "Failed to extract and remove embedded signature"
	else
		echo_success "Successful extract and removed embedded signature"
	fi

	$SBATTACH \
	 --attach ${output_sig} \
	 --print \
	 $output_reattach

	if [ $? -ne 0 ]
	then
		echo_fail "Failed to attach embedded signature"
	else
		echo_success "Successful attach embedded signature"
	fi

	diff $output_reattach $output

	if [ $? -ne 0 ]
	then
		echo_fail "Re-attached file differs from original"
	else
		echo_success "Re-attached file identical to original"
	fi
}

sbattach_cert_detached() {
	local output="$TMPDIR/$(basename $EFIFILE).pk7"
	local output2="$TMPDIR/$(basename $EFIFILE).signed"

	echo_info "Leancrypto: sbattach PKCS#7 signature of PE/COFF file using the X.509 certificate and associated PKCS#8 private key as signer"

	$SBATTACH \
	 --attach $output \
	 --print \
	 $output2

	if [ $? -ne 0 ]
	then
		echo_fail "Failed sbattach detached signature"
	else
		echo_success "Successful sbattach detached signature"
	fi
}

################################################################################
# TEST 1
#
# Leancrypto generation of key/cert and use it for sbsign and sbattach
#
lc_sbsign() {
	lc_generate_cert_pkcs8 $1

	sbsign_cert
	sbdetach_cert
	sbsign_cert_detached
	sbattach_cert_detached
}

################################################################################
# TEST 2
#
# Leancrypto generation of key/cert and use it for sbsign and sbattach usng
# PEM key/certificate format
#
lc_sbsign_pem() {
	lc_generate_cert_pkcs8 $1 "--pem-output"

	sbsign_cert
	sbdetach_cert
	sbsign_cert_detached
	sbattach_cert_detached
}

case $TESTTYPE
in
	"ML-DSA87" | "ML-DSA-87")
		lc_sbsign "ML-DSA87"
		lc_sbsign_pem "ML-DSA87"
	;;
	"ML-DSA65" | "ML-DSA-65")
		lc_sbsign "ML-DSA65"
		lc_sbsign_pem "ML-DSA65"
	;;
	"ML-DSA44" | "ML-DSA-44")
		lc_sbsign "ML-DSA44"
		lc_sbsign_pem "ML-DSA44"
	;;
	"ML-DSA87-ED448")
		lc_sbsign "ML-DSA87-ED448"
		lc_sbsign_pem "ML-DSA87-ED448"
	;;
	"ML-DSA65-ED25519")
		lc_sbsign "ML-DSA65-ED25519"
		lc_sbsign_pem "ML-DSA65-ED25519"
	;;
	"ML-DSA44-ED25519")
		lc_sbsign "ML-DSA44-ED25519"
		lc_sbsign_pem "ML-DSA44-ED25519"
	;;
	"SLH-DSA-SHAKE-128F" | "SLH-DSA-SHAKE-128f")
		lc_sbsign "SLH-DSA-SHAKE-128F"
		lc_sbsign_pem "SLH-DSA-SHAKE-128F"
	;;
	"SLH-DSA-SHAKE-128S" | "SLH-DSA-SHAKE-128s")
		lc_sbsign "SLH-DSA-SHAKE-128S"
		lc_sbsign_pem "SLH-DSA-SHAKE-128S"
	;;
	"SLH-DSA-SHAKE-192F" | "SLH-DSA-SHAKE-192f")
		lc_sbsign "SLH-DSA-SHAKE-192F"
		lc_sbsign_pem "SLH-DSA-SHAKE-192F"
	;;
	"SLH-DSA-SHAKE-192S" | "SLH-DSA-SHAKE-192s")
		lc_sbsign "SLH-DSA-SHAKE-192S"
		lc_sbsign_pem "SLH-DSA-SHAKE-192S"
	;;
	"SLH-DSA-SHAKE-256F" | "SLH-DSA-SHAKE-256f")
		lc_sbsign "SLH-DSA-SHAKE-256F"
		lc_sbsign_pem "SLH-DSA-SHAKE-256F"
	;;
	"SLH-DSA-SHAKE-256S" | "SLH-DSA-SHAKE-256s")
		lc_sbsign "SLH-DSA-SHAKE-256S"
		lc_sbsign_pem "SLH-DSA-SHAKE-256S"
	;;
	*)
		echo_fail "Unknown test type $TESTTYPE"
	;;
esac

################################################################################
report_result
