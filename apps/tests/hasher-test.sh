#!/bin/bash
#
# Copyright (C) 2017 - 2025, Stephan Mueller <smueller@chronox.de>
#
# License: see LICENSE file in root directory
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
# WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#

DIRNAME="$(dirname "$0")"
. "$DIRNAME/libtest.sh"

LC_HASHER=$1
COMP_HASHER=$2

if [ ! -x "$LC_HASHER" ]
then
	echo_fail "Leancrypto hasher $LC_HASHER does not exist"
	exit 77
fi

run_hasher()
{
	"$@"
}

CHKFILE="${TMPDIR}/chk.$$"
ANOTHER="${TMPDIR}/test.$$"

touch $ANOTHER
trap "rm -f $ANOTHER $CHKFILE" 0 1 2 3 15

>$CHKFILE
run_hasher $LC_HASHER -c $CHKFILE
if [ $? -eq 0 ]
then
	echo_fail "Verification of empty checker file with hasher $LC_HASHER did not fail"
else
	echo_pass "Failure on empty checker file for $LC_HASHER"
fi

echo >$CHKFILE
run_hasher $LC_HASHER -c $CHKFILE
if [ $? -eq 0 ]
then
	echo_fail "Verification of empty line checker file with hasher $LC_HASHER did not fail"
else
	echo_pass "Failure on empty line checker file for $LC_HASHER"
fi


if [ -x "$COMP_HASHER" ]
then
	run_hasher $COMP_HASHER $0 | sed -E 's/(\w+\s)\s/\1*/' >$CHKFILE
	run_hasher $LC_HASHER --status -c $CHKFILE
	if [ $? -eq 0 ]
	then
		echo_pass "Parsing checker file with asterisk with $LC_HASHER"
	else
		echo_fail "Parsing checker file with asterisk (binary mode) with $LC_HASHER failed"
	fi
else
	echo_deact "Compare hasher $COMP_HASHER does not exist"
fi

run_hasher $LC_HASHER $0 | run_hasher $LC_HASHER --status -c -
if [ $? -eq 0 ]
then
	echo_pass "Checker file '-' interpretation with $LC_HASHER"
else
	echo_fail "Checker file '-' interpretation with $LC_HASHER failed"
fi

run_hasher $LC_HASHER $0 - <$CHKFILE >/dev/null
if [ $? -eq 0 ]
then
	echo_pass "Input file '-' interpretation with $LC_HASHER"
else
	echo_fail "Input file '-' interpretation with $LC_HASHER failed"
fi

rm -f $CHKFILE

hash=$(basename $LC_HASHER)
hash=${hash%%sum}

run_hasher $LC_HASHER $0 $ANOTHER > $CHKFILE
if [ $? -ne 0 ]
then
	echo_fail "Generation of hashes with hasher $LC_HASHER failed"
fi

if [ ! -f "$CHKFILE" ]
then
	echo_fail "Generation of checker file $CHKFILE with hasher $LC_HASHER failed"
fi

opensslcmd=$(type -p openssl)

if [ -x "$opensslcmd" ]
then
	a=$($opensslcmd dgst -$hash $0)
	if [ $? -ne 0 ]
	then
		echo_deact "Hash type $hash is not supported by OpenSSL"
	else
		a=$(echo $a | cut -f 2 -d" ")
		b=$(run_hasher $LC_HASHER $0 | cut -f 1 -d" ")
		if [ x"$a" != x"$b" ]
		then
			echo_fail "Hash calculation for $LC_HASHER failed"
		else
			echo_pass "Hash calculation for $LC_HASHER matches OpenSSL"
		fi
	fi
fi

echo "==================================================================="
echo "Number of failures: $failures"

exit $failures
