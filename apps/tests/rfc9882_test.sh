#!/bin/bash
#
# Written by Stephan Mueller <smueller@chronox.de>
#
# Checker script to validate the RFC9882 vectors. To utilize this script,
# perform the following steps:
#
# 1. compile leancrypto with lc_pkcs7_generator tool enabled
# 2. update variables LC_PKCS7_GENERATOR below to point to the respective
#    application
# 3. Execute this script
#
# Expected result: no failures should be shown
#

LC_PKCS7_GENERATOR="lc_pkcs7_generator"
SBVERIFY="sbverify"

TESTVECTOR=$1

if [ -n "$2" ]
then
	LC_PKCS7_GENERATOR=$2
fi

if [ ! -x "$LC_PKCS7_GENERATOR" ]
then
	exit 77
fi

global_failure_count=0

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

	local type=$(basename $inputfile)
	type=${type##*mldsa}
	type=${type%%.pem}

	echo "=== Checking file $inputfile with Leancrypto ==="
	$LC_PKCS7_GENERATOR --check-data "ML-DSA-${type} signed-data example with signed attributes" --check-kid 159ffe6f22fd5cc42c524df6fd5e28d0de38f34e --print-pkcs7-noverify $inputfile
	if [ $? -ne 0 ]
	then
		echo_fail "Parsing of file $inputfile was unsuccessful"
	else
		echo_success "Parsing of file $inputfile was successful"
	fi
}

check_one $TESTVECTOR

################################################################################
report_result
