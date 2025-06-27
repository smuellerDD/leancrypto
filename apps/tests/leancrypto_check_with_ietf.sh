#!/bin/bash
#
# Written by Stephan Mueller <smueller@chronox.de>
#
# Checker script to validate the X.509 certificates created by other
# crypto providers stored in
# https://github.com/IETF-Hackathon/pqc-certificates/providers
#
# To utilize this script, perform the following steps:
#
# 1. compile leancrypto with X.509 generator enabled
# 2. update variable LC_X509_CHECKER below to point to the lc_x509_generator
#    tool
# 3. cd into the https://github.com/IETF-Hackathon/pqc-certificates/providers
#    directory
# 4. Execute this script
#
# Expected result: no failures should be shown
#

LC_X509_CHECKER="lc_x509_generator"

if [ -n "$1" ]
then
	LC_X509_CHECKER=$1
fi

if [ ! -x "$LC_X509_CHECKER" ]
then
	exit 77
fi

SRCDIR="."
if [ -n "$2" ]
then
	SRCDIR=$2
fi

#check presence of unzip
unzip > /dev/null 2>&1
if [ $? -ne 0 ]
then
	exit 0
fi

TMPDIR="./tmp"

global_failure_count=0

trap "rm -rf $TMPDIR" 0 1 2 3 15

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
}

echo_info()
{
	echo $(color "magenta")[INFO]$(color off) "$@"
}

check_one() {
	local inputfile=$1

	if [ ! -f "$inputfile" ]
	then
		echo_fail "Cannot find $inputfile"
		exit 1
	fi

	echo "=== File $inputfile ==="
	$LC_X509_CHECKER --check-selfsigned --print-x509 $inputfile
	if [ $? -ne 0 ]
	then
		echo_fail "Parsing of file $inputfile was unsuccessful"
		global_failure_count=$(($global_failure_count+1))
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

extract_files() {
	local zipfile="${SRCDIR}/$1"

	if [ ! -f "$zipfile" ]
	then
		echo_fail "Cannot find $zipfile"
		exit 1
	fi

	rm -rf $TMPDIR
	mkdir $TMPDIR
	unzip $zipfile -d $TMPDIR
}

bc_test() {
	local slh_dsa_files="slh-dsa-shake-128f-2.16.840.1.101.3.4.3.27_ta.der slh-dsa-shake-128s-2.16.840.1.101.3.4.3.26_ta.der slh-dsa-shake-192f-2.16.840.1.101.3.4.3.29_ta.der slh-dsa-shake-192s-2.16.840.1.101.3.4.3.28_ta.der slh-dsa-shake-256f-2.16.840.1.101.3.4.3.31_ta.der slh-dsa-shake-256s-2.16.840.1.101.3.4.3.30_ta.der"
	local composite_ml_dsa_files="MLDSA44-Ed25519-SHA512-2.16.840.1.114027.80.8.1.23_ta.der MLDSA65-Ed25519-SHA512-2.16.840.1.114027.80.8.1.30_ta.der"
	local ml_dsa_files="ml-dsa-44-2.16.840.1.101.3.4.3.17_ta.der ml-dsa-65-2.16.840.1.101.3.4.3.18_ta.der ml-dsa-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$slh_dsa_files $ml_dsa_files"
	#local files="$slh_dsa_files $composite_ml_dsa_files $ml_dsa_files"

	extract_files "bc/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

redhound_test() {
	local subdir="artifacts_certs_r5"
	local slh_dsa_files="$subdir/slh-dsa-shake-128f-2.16.840.1.101.3.4.3.27_ta.der $subdir/slh-dsa-shake-128s-2.16.840.1.101.3.4.3.26_ta.der $subdir/slh-dsa-shake-192f-2.16.840.1.101.3.4.3.29_ta.der $subdir/slh-dsa-shake-192s-2.16.840.1.101.3.4.3.28_ta.der $subdir/slh-dsa-shake-256f-2.16.840.1.101.3.4.3.31_ta.der $subdir/slh-dsa-shake-256s-2.16.840.1.101.3.4.3.30_ta.der"
	local ml_dsa_files="$subdir/ml-dsa-44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ml-dsa-65-2.16.840.1.101.3.4.3.18_ta.der $subdir/ml-dsa-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$slh_dsa_files $ml_dsa_files"

	extract_files "carl-redhound/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

cht_test() {
	local subdir="./"
	local slh_dsa_files="$subdir/SLH-DSA-SHAKE-128f-2.16.840.1.101.3.4.3.27_ta.der $subdir/SLH-DSA-SHAKE-128s-2.16.840.1.101.3.4.3.26_ta.der $subdir/SLH-DSA-SHAKE-192f-2.16.840.1.101.3.4.3.29_ta.der $subdir/SLH-DSA-SHAKE-192s-2.16.840.1.101.3.4.3.28_ta.der $subdir/SLH-DSA-SHAKE-256f-2.16.840.1.101.3.4.3.31_ta.der $subdir/SLH-DSA-SHAKE-256s-2.16.840.1.101.3.4.3.30_ta.der"
	local composite_ml_dsa_files="$subdir/id-MLDSA44-Ed25519-2.16.840.1.114027.80.8.1.23_ta.der $subdir/id-MLDSA65-Ed25519-2.16.840.1.114027.80.8.1.30_ta.der"
	local ml_dsa_files="$subdir/ML-DSA-44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ML-DSA-65-2.16.840.1.101.3.4.3.18_ta.der $subdir/ML-DSA-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$slh_dsa_files $ml_dsa_files"
	#local files="$slh_dsa_files $composite_ml_dsa_files $ml_dsa_files"

	extract_files "cht/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

corey_digicert_test() {
	local ml_dsa_files="ML-DSA-44-2.16.840.1.101.3.4.3.17_ta.der ML-DSA-65-2.16.840.1.101.3.4.3.18_ta.der ML-DSA-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$ml_dsa_files"

	extract_files "corey-digicert/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

crypto4a_test() {
	local subdir="artifacts_certs_r5"
	local ml_dsa_files="$subdir/ml_dsa_44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ml_dsa_65-2.16.840.1.101.3.4.3.18_ta.der $subdir/ml_dsa_87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$slh_dsa_files $ml_dsa_files"

	extract_files "cryptonext/artifacts_certs_r4.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

cryptonext_test() {
	local subdir="artifacts_certs_r5"
	local slh_dsa_files="$subdir/SLH-DSA-SHAKE-128f-2.16.840.1.101.3.4.3.27_ta.der $subdir/SLH-DSA-SHAKE-128s-2.16.840.1.101.3.4.3.26_ta.der $subdir/SLH-DSA-SHAKE-192f-2.16.840.1.101.3.4.3.29_ta.der $subdir/SLH-DSA-SHAKE-192s-2.16.840.1.101.3.4.3.28_ta.der $subdir/SLH-DSA-SHAKE-256f-2.16.840.1.101.3.4.3.31_ta.der $subdir/SLH-DSA-SHAKE-256s-2.16.840.1.101.3.4.3.30_ta.der"
	local ml_dsa_files="$subdir/ML-DSA-44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ML-DSA-65-2.16.840.1.101.3.4.3.18_ta.der $subdir/ML-DSA-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$slh_dsa_files $ml_dsa_files"

	extract_files "cryptonext/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

entrust_test() {
	local subdir="artifacts"
	local ml_dsa_files="$subdir/ML-DSA-44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ML-DSA-44-2.16.840.1.101.3.4.3.18_ta.der $subdir/ML-DSA-44-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$ml_dsa_files"

	extract_files "entrust/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

kris_test() {
	local subdir="artifacts_certs_r4"
	local ml_dsa_files="$subdir/ml-dsa-44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ml-dsa-65-2.16.840.1.101.3.4.3.18_ta.der $subdir/ml-dsa-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$ml_dsa_files"

	extract_files "kris/artifacts_certs_r4.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

openssl_test() {
	local subdir="./"
	local ml_dsa_files="$subdir/ml-dsa-44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ml-dsa-65-2.16.840.1.101.3.4.3.18_ta.der $subdir/ml-dsa-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$ml_dsa_files"

	extract_files "openssl/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

seventhsense_test() {
	local slh_dsa_files="SlhDsaShake128f-2.16.840.1.101.3.4.3.27_ta.der SlhDsaShake128s-2.16.840.1.101.3.4.3.26_ta.der SlhDsaShake192f-2.16.840.1.101.3.4.3.29_ta.der SlhDsaShake192s-2.16.840.1.101.3.4.3.28_ta.der SlhDsaShake256f-2.16.840.1.101.3.4.3.31_ta.der SlhDsaShake256s-2.16.840.1.101.3.4.3.30_ta.der"
	local composite_ml_dsa_files="MlDsa44Ed25519-2.16.840.1.114027.80.8.1.23_ta.der MlDsa65Ed25519-2.16.840.1.114027.80.8.1.30_ta.der"
	local ml_dsa_files="MlDsa44-2.16.840.1.101.3.4.3.17_ta.der MlDsa65-2.16.840.1.101.3.4.3.18_ta.der MlDsa87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$slh_dsa_files $ml_dsa_files"
	#local files="$slh_dsa_files $composite_ml_dsa_files $ml_dsa_files"

	extract_files "seventhsense.ai/artifact_certs_r4.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

leancrypto_test() {
	local subdir="artifacts_certs_r5"
	local slh_dsa_files="$subdir/SLH-DSA-SHAKE-128F-2.16.840.1.101.3.4.3.27_ta.der $subdir/SLH-DSA-SHAKE-128S-2.16.840.1.101.3.4.3.26_ta.der $subdir/SLH-DSA-SHAKE-192F-2.16.840.1.101.3.4.3.29_ta.der $subdir/SLH-DSA-SHAKE-192S-2.16.840.1.101.3.4.3.28_ta.der $subdir/SLH-DSA-SHAKE-256F-2.16.840.1.101.3.4.3.31_ta.der $subdir/SLH-DSA-SHAKE-256S-2.16.840.1.101.3.4.3.30_ta.der"
	local composite_ml_dsa_files="$subdir/ML-DSA44-ED25519-SHA512-2.16.840.1.114027.80.9.1.2_ta.der $subdir/ML-DSA65-ED25519-SHA512-2.16.840.1.114027.80.9.1.11_ta.der $subdir/ML-DSA87-ED448-SHAKE256-2.16.840.1.114027.80.9.1.14_ta.der"
	local ml_dsa_files="$subdir/ML-DSA44-2.16.840.1.101.3.4.3.17_ta.der $subdir/ML-DSA65-2.16.840.1.101.3.4.3.18_ta.der $subdir/ML-DSA87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$slh_dsa_files $composite_ml_dsa_files $ml_dsa_files"

	extract_files "leancrypto/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

python_ref_test() {
	local composite_ml_dsa_files="id-MLDSA44-Ed25519-SHA512-2.16.840.1.114027.80.9.1.2_ta.der id-MLDSA65-Ed25519-SHA512-2.16.840.1.114027.80.9.1.11_ta.der id-MLDSA87-Ed448-SHAKE256-2.16.840.1.114027.80.9.1.14_ta.der"
	local ml_dsa_files="id-ML-DSA-44-2.16.840.1.101.3.4.3.17_ta.der id-ML-DSA-65-2.16.840.1.101.3.4.3.18_ta.der id-ML-DSA-87-2.16.840.1.101.3.4.3.19_ta.der"

	local files="$composite_ml_dsa_files $ml_dsa_files"

	extract_files "python_reference/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

composite_ref_imp_test() {
	local composite_ml_dsa_files="id-MLDSA44-Ed25519-SHA512-2.16.840.1.114027.80.9.1.2_ta.der id-MLDSA65-Ed25519-SHA512-2.16.840.1.114027.80.9.1.11_ta.der id-MLDSA87-Ed448-SHAKE256-2.16.840.1.114027.80.9.1.14_ta.der"
	local ml_dsa_files="id-ML-DSA-44-2.16.840.1.101.3.4.3.17_ta.der"

	#local files="$composite_ml_dsa_files $ml_dsa_files"
	local files="$ml_dsa_files"

	extract_files "composite-ref-impl/artifacts_certs_r5.zip"
	for i in $files
	do
		check_one "$TMPDIR/$i"
	done
}

bc_test
redhound_test
cht_test
corey_digicert_test
cryptonext_test
entrust_test
kris_test
openssl_test
seventhsense_test
leancrypto_test
composite_ref_imp_test
python_ref_test

report_result
