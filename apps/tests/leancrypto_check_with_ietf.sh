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
# 2. update variables LC_X509_CHECKER and LC_PKCS7_CHECKER below to point to the
#    lc_x509_generator and lc_pkcs7_generator tool path
# 3. cd into the https://github.com/IETF-Hackathon/pqc-certificates/providers
#    directory
# 4. Execute this script
#
# Expected result: no failures should be shown
#

LC_X509_CHECKER="lc_x509_generator"
LC_PKCS7_CHECKER="lc_pkcs7_generator"

if [ -n "$1" ]
then
	LC_X509_CHECKER=$1
fi

if [ ! -x "$LC_X509_CHECKER" ]
then
	exit 77
fi

if [ -n "$2" ]
then
	LC_PKCS7_CHECKER=$2
fi

if [ ! -x "$LC_PKCS7_CHECKER" ]
then
	exit 77
fi


SRCDIR="."
if [ -n "$3" ]
then
	SRCDIR=$3
fi

#check presence of unzip
unzip > /dev/null 2>&1
if [ $? -ne 0 ]
then
	exit 0
fi

TMPDIR="./tmp.$$"

STATUSOUT="$TMPDIR"
if [ -n "$4" ]
then
	STATUSOUT=$4
fi

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

statusfile=""
doc_init() {
	local outputfile=$1

	echo "key_algorithm_oid,type,test_result" > $outputfile
	statusfile="$outputfile"
}

doc_one() {
	local oid=$1
	local type=$2 #both, expandedkey, seed, priv
	local res=$3 #Y, N

	touch $statusfile
	echo "$oid,$type,$res" >> $statusfile
}

lc_sign_cert() {
	local pk_file=$1
	local sk_file=$2

	echo_info "Leancrypto: Create PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$LC_PKCS7_CHECKER \
	 --md SHA2-512 \
	 -i ${pk_file} \
	 -o ${pk_file}.p7b \
	 --x509-signer  ${pk_file} \
	 --signer-sk-file ${sk_file}

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto signature generation"
		return 1
	else
		echo_success "Successful leancrypto signature generation"
		return 0
	fi
}

lc_verify_cert() {
	local pk_file=$1

	echo_info "Leancrypto: Verify PKCS#7 signature of X.509 certificate using the X.509 certificate and associated PKCS#8 private key as signer"

	$LC_PKCS7_CHECKER \
	 --print-pkcs7 ${pk_file}.p7b \
	 -i ${pk_file} \
	 --trust-anchor ${pk_file}

	if [ $? -ne 0 ]
	then
		echo_fail "Failed leancrypto signature verification"
		return 1
	else
		echo_success "Successful leancrypto signature verification"
		return 0
	fi
}

check_one() {
	local certfile=$1
	local certcheck_only=$2
	local oid=$3
	local type="priv"

	if [ ! -f "$certfile" ]
	then
		echo_fail "Cannot find $certfile"
		exit 1
	fi

	echo "=== File $certfile ==="
	$LC_X509_CHECKER --print-x509 $certfile
	#$LC_X509_CHECKER --check-selfsigned --print-x509 $certfile
	if [ $? -ne 0 ]
	then
		echo_fail "Parsing of file $certfile was unsuccessful"
		global_failure_count=$(($global_failure_count+1))
		if [ -n "$oid" ]
		then
			doc_one "$oid" "$type" "N"
		fi
		return
	fi

	if [ $certcheck_only -eq 1 ]
	then
		echo_success "Parsing of file $certfile was successful"
		if [ -n "$oid" ]
		then
			doc_one "$oid" "$type" "Y"
		fi
		return
	fi

	local privkey_part=${certfile%%_ta.der}

	for i in "priv" "seed_priv" "seed" "both_priv" "expandedkey_priv"
	do
		local privkey="${privkey_part}_${i}.der"
		if [ ! -f "$privkey" ]
		then
			echo_info "Cannot find private key $privkey for $certfile"
			continue
		fi

		if [ x"$i" = x"priv" ]
		then
			type="priv"
		elif [ x"$i" = x"seed_priv" ]
		then
			type="seed"
		elif [ x"$i" = x"seed" ]
		then
			type="seed"
		elif [ x"$i" = x"both_priv" ]
		then
			type="both"
		elif [ x"$i" = x"expandedkey_priv" ]
		then
			type="expandedkey"
		fi

		rm -f ${certfile}.p7b

		lc_sign_cert $certfile $privkey
		if [ $? -ne 0 ]
		then
			echo_fail "Generating signature of file $certfile was unsuccessful"
			global_failure_count=$(($global_failure_count+1))
			if [ -n "$oid" ]
			then
				doc_one "$oid" "$type" "N"
			fi
			continue
		fi

		lc_verify_cert $certfile

		# We try to validate, but only print the output without logging
		# the result - this is due to the fact that some provider like
		# CHT do not include the root CA.
# 		if [ $? -ne 0 ]
# 		then
# 			echo_fail "Verifying signature of file $certfile was unsuccessful"
# 			global_failure_count=$(($global_failure_count+1))
# 			if [ -n "$oid" ]
# 			then
# 				doc_one "$oid" "$type" "N"
# 			fi
# 			continue
# 		fi

		echo_success "Parsing of file $certfile was successful"
		if [ -n "$oid" ]
		then
			doc_one "$oid" "$type" "Y"
		fi
	done
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
	local provider=$(dirname $1)
	local zipfile="${SRCDIR}/$1"

	if [ ! -f "$zipfile" ]
	then
		echo_fail "Cannot find $zipfile"
		exit 1
	fi

	rm -rf $TMPDIR
	mkdir $TMPDIR
	unzip $zipfile -d $TMPDIR

	if [ ! -d $STATUSOUT ]
	then
		mkdir $STATUSOUT
		if [ $? -ne 0 ]
		then
			echo_fail "Cannot create $STATUSOUT"
			exit 1
		fi
	fi
	doc_init $STATUSOUT/${provider}_leancrypto.csv
}

ml_dsa_oids="2.16.840.1.101.3.4.3.17 2.16.840.1.101.3.4.3.18 2.16.840.1.101.3.4.3.19"
composite_ml_dsa_oids="1.3.6.1.5.5.7.6.39 1.3.6.1.5.5.7.6.48 1.3.6.1.5.5.7.6.51"
slh_dsa_oids="2.16.840.1.101.3.4.3.26 2.16.840.1.101.3.4.3.27 2.16.840.1.101.3.4.3.28 2.16.840.1.101.3.4.3.29 2.16.840.1.101.3.4.3.30 2.16.840.1.101.3.4.3.31"

bc_test() {
	local oids="$ml_dsa_oids $slh_dsa_oids"
	#local oids="$ml_dsa_oids $composite_ml_dsa_oids $slh_dsa_oids"
	local file=""

	extract_files "bc/artifacts_certs_r5.zip"
	for i in $oids
	do
		file=$TMPDIR/*$i*_ta.der
		for j in $file
		do
			echo $j | grep -q "catalyst" && continue
			echo $j | grep -q "chameleon" && continue
			echo $j | grep -q "composite_1.2.840" && continue

			# TODO set 1 -> 0 when certificates received an SKID
			check_one $j 1 $i
		done
	done
}

redhound_test() {
	local subdir="artifacts_certs_r5"
	local oids="$ml_dsa_oids $slh_dsa_oids"

	extract_files "carl-redhound/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/$subdir/*$i*_ta.der 0 $i
	done
}

cht_test() {
	local subdir="./"
	local oids="$ml_dsa_oids $composite_ml_dsa_oids $slh_dsa_oids"

	extract_files "cht/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/$subdir/*$i*_ta.der 0 $i
	done
}

corey_digicert_test() {
	local oids="$ml_dsa_oids"

	extract_files "corey-digicert/artifacts_certs_r5.zip"
	for i in $oids
	do
		# TODO set 1 -> when either the PKCS#8 blobs are version 1
		# or leancrypto received support for version 2
		check_one $TMPDIR/$subdir/*$i*_ta.der 1 $i
	done
}

crypto4a_test() {
	local oids="$ml_dsa_oids $composite_ml_dsa_oids $slh_dsa_oids"

	extract_files "crypto4a/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/*$i*_ta.der 0 $i
	done
}

cryptonext_test() {
	local subdir="artifacts_certs_r5"
	local oids="$ml_dsa_oids $composite_ml_dsa_oids $slh_dsa_oids"

	extract_files "cryptonext/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/$subdir/*$i*_ta.der 0 $i
	done
}

entrust_test() {
	local subdir="artifacts"
	local oids="$ml_dsa_oids $composite_ml_dsa_oids $slh_dsa_oids"

	extract_files "entrust/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/$subdir/*$i*_ta.der 0 $i
	done
}

kris_test() {
	local subdir="artifacts_certs_r4"
	local oids="$ml_dsa_oids"

	extract_files "kris/artifacts_certs_r4.zip"
	for i in $oids
	do
		check_one $TMPDIR/$subdir/*$i*_ta.der 0 $i
	done
}

openjdk_test() {
	local oids="$ml_dsa_oids"

	extract_files "openjdk/artifacts_certs_r5.zip"
	for i in $oids
	do
		# TODO set 1 -> 0 when certificates received an SKID
		check_one $TMPDIR/*$i*_ta.der 1 $i
	done
}

openssl_test() {
	local subdir="./"
	local oids="$ml_dsa_oids $slh_dsa_oids"

	extract_files "openssl/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/$subdir/*$i*_ta.der 0 $i
	done
}

seventhsense_test() {
	#local oids="$ml_dsa_oids $composite_ml_dsa_oids $slh_dsa_oids"
	local oids="$ml_dsa_oids $slh_dsa_oids"

	extract_files "seventhsense.ai/artifact_certs_r4.zip"
	for i in $oids
	do
		check_one $TMPDIR/*$i*_ta.der 0 $i
	done
}

safelogic_test() {
	local oids="$ml_dsa_oids $slh_dsa_oids"

	extract_files "safelogic/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/*$i*_ta.der 0 $i
	done

	# TODO set 1 -> 0 when private key complies with draft (64 bytes size only)
	check_one $TMPDIR/$subdir/*1.3.6.1.5.5.7.6.48*_ta.der 1 1.3.6.1.5.5.7.6.48
}

leancrypto_test() {
	local subdir="artifacts_certs_r5"
	local oids="$ml_dsa_oids $composite_ml_dsa_oids $slh_dsa_oids"

	extract_files "leancrypto/artifacts_certs_r5.zip"
	for i in $oids
	do
		check_one $TMPDIR/$subdir/*$i*_ta.der 1 $i
	done
}

composite_ref_imp_test() {
	local oids="$ml_dsa_oids $composite_ml_dsa_oids"

	extract_files "composite-ref-impl/artifacts_certs_r5.zip"
	for i in $oids
	do
		# TODO set 1 -> 0 when certificates received an SKID
		check_one $TMPDIR/$subdir/*$i*_ta.der 1 $i
	done
}

bc_test
redhound_test
cht_test
corey_digicert_test
crypto4a_test
cryptonext_test
entrust_test
kris_test
openjdk_test
openssl_test
seventhsense_test
safelogic_test
leancrypto_test
composite_ref_imp_test

report_result
