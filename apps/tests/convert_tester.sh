#!/bin/bash
#
# Written by Stephan Mueller <smueller@chronox.de>
#
# Checker script to validate the PEM - DER conversion support
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
LC_SHA256SUM="sha256sum"

if [ -n "$1" ]
then
	LC_X509_GENERATOR=$1
fi

if [ -n "$2" ]
then
	LC_SHA256SUM=$2
fi

if [ ! -x "$LC_X509_GENERATOR" ]
then
	exit 77
fi

if [ ! -x "$LC_SHA256SUM" ]
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
	local file1=$1
	local file2=$2

	if [ ! -f "$file1" ]
	then
		echo_fail "Cannot find $file1"
		exit 1
	fi
	if [ ! -f "$file2" ]
	then
		echo_fail "Cannot find $file2"
		exit 1
	fi

	digest1=$($LC_SHA256SUM $file1 | cut -f1 -d" ")
	digest2=$($LC_SHA256SUM $file2 | cut -f1 -d" ")

	if [ x"$digest1" != x"$digest2" ]
	then
		echo_fail "Files $file1 and $file2 mismatch"
		exit 1
	else
		echo_pass "Files $file1 and $file2 match"
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
}

lc_convert_pk() {
	local infile=$1
	local outfile=$2
	local pem_output=$3

	rm -f ${outfile}

	echo_info "Leancrypto: Convert certificate $infile to $outfile"

	$LC_X509_GENERATOR \
	 $pem_output \
	 --convert \
	 --x509-signer $infile \
	 --outfile $outfile

	if [ $? -ne 0 ]
	then
		echo_fail "Failed to convert certificate"
	else
		echo_success "Successful conversion of certificate"
	fi
}

lc_convert_sk() {
	local infile=$1
	local outfile=$2
	local pem_output=$3

	rm -f ${outfile}

	echo_info "Leancrypto: Convert secret key $infile to $outfile"

	$LC_X509_GENERATOR \
	 $pem_output \
	 --convert \
	 --signer-sk-file $infile \
	 --sk-file $outfile

	if [ $? -ne 0 ]
	then
		echo_fail "Failed to convert secret key"
	else
		echo_success "Successful conversion of ecret key"
	fi
}

################################################################################
# TEST 1
#
lc_convert_sk_der_pem() {
	lc_generate_cert_pkcs8 $1

	lc_convert_sk "${sk_file}" "${sk_file}.pem" "--pem-output"
	lc_convert_sk "${sk_file}.pem" "${sk_file}.2"
	check_one "${sk_file}" "${sk_file}.2"
}

################################################################################
# TEST 2
#
lc_convert_sk_pem_der() {
	lc_generate_cert_pkcs8 $1 "--pem-output"

	lc_convert_sk "${sk_file}" "${sk_file}.der"
	lc_convert_sk "${sk_file}.der" "${sk_file}.2" "--pem-output"
	check_one "${sk_file}" "${sk_file}.2"
}

################################################################################
# TEST 3
#
lc_convert_pk_der_pem() {
	lc_generate_cert_pkcs8 $1

	lc_convert_pk "${pk_file}" "${pk_file}.pem" "--pem-output"
	lc_convert_pk "${pk_file}.pem" "${pk_file}.2"
	check_one "${pk_file}" "${pk_file}.2"
}

################################################################################
# TEST 4
#
lc_convert_pk_pem_der() {
	lc_generate_cert_pkcs8 $1 "--pem-output"

	lc_convert_pk "${pk_file}" "${pk_file}.der"
	lc_convert_pk "${pk_file}.der" "${pk_file}.2" "--pem-output"
	check_one "${pk_file}" "${pk_file}.2"
}

lc_convert_sk_der_pem "ML-DSA87"
lc_convert_sk_pem_der "ML-DSA65-ED25519"
lc_convert_pk_der_pem "SLH-DSA-SHAKE-192F"
lc_convert_pk_pem_der "ML-DSA87-ED448"

################################################################################
report_result
