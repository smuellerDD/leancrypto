#!/bin/sh
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

TESTER="status_tester"
JQ="/usr/bin/jq"

if [ -n "$1" ]
then
	TESTER=$1
fi

if [ ! -x "$JQ" ]
then
	exit 77
fi

global_failure_count=0

trap "rm -rf $TMPDIR" 0 1 2 3 15

color()
{
	bg=0
	echo "\033[0m"
	while [ $# -gt 0 ]; do
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
		if [ $code -ne 0 ]
		then
			echo "\033[$(printf "%02d" $((code+bg)))m"
		fi
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

test_json() {
	$TESTER | jq ".version"
	if [ $? -ne 0 ]
	then
		echo_fail "Parsing JSON status was unsuccessful"
	else
		echo_success "Parsing JSON status was successful"
	fi
}

test_json
################################################################################
report_result
