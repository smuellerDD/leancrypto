#!/bin/bash
#
# Written by Stephan Mueller <smueller@chronox.de>
#
# Checker script to validate the sbvarsign tool. To utilize this script, perform
# the following steps:
#
# 1. compile leancrypto with sbvarign tool enabled
# 2. update variable SBSIGLIST, SHA256SUM below to point to the respective
#    applications
# 3. Execute this script
#
# Expected result: no failures should be shown
#

SBSIGLIST="sbsiglist"
SHA256SUM="sha256sum"

if [ -n "$1" ]
then
	SBSIGLIST=$1
fi

if [ -n "$2" ]
then
	SHA256SUM=$2
fi

if [ ! -x "$SBSIGLIST" ]
then
	exit 77
fi

if [ ! -x "$SHA256SUM" ]
then
	exit 77
fi

TMPDIR="./tmp.$$"

global_failure_count=0

trap "rm -rf $TMPDIR" 0 1 2 3 15
mkdir $TMPDIR

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

sbsiglist_test() {
	echo_info "Leancrypto: sbsiglist create"

	local file="$TMPDIR/testdata"
	local file_sha="$TMPDIR/testdata_sha256"

	echo "testdata" > $file
	$SHA256SUM -b $file > $file_sha

	$SBSIGLIST \
	 --owner "74a760a6-ab92-4ba9-8bde-d7fb70a6e2bb" \
	 --type "x509" \
	 $file

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto sbsiglist X.509 generation"
	else
		echo_success "Successful leancrypto sbsiglist X.509 generation"
	fi

	$SBSIGLIST \
	 --owner "74a760a6-ab92-4ba9-8bde-d7fb70a6e2bb" \
	 --type "sha256" \
	 $file_sha

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto sbsiglist SHA-256 generation"
	else
		echo_success "Successful leancrypto sbsiglist SHA-256 generation"
	fi
}

################################################################################
# TEST 1
#
# Leancrypto generation of key/cert and use it for signature generation and
# verification
#
lc_sbvarsign() {
	sbsiglist_test
}

lc_sbvarsign

################################################################################
report_result
