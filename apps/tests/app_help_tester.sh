#!/bin/sh
#
# Copyright (C) 2017 - 2026, Stephan Mueller <smueller@chronox.de>
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

# Solaris cannot handle "local" keywords
os=$(uname -s 2>/dev/null)
if [ x"$os" = x"SunOS" ]
then
	exit 77
fi

DIRNAME="$(dirname "$0")"
. "$DIRNAME/libtest.sh"

APP=$1

if [ ! -x "$APP" ]
then
	echo_fail "Leancrypto hasher $APP does not exist"
	exit 77
fi

run_hasher()
{
	"$@"
}

run_hasher $APP --help
if [ $? -ne 0 ]
then
	echo_fail "Help display of $APP failed"
else
	echo_pass "Help display of $APP passed"
fi

echo "==================================================================="
echo "Number of failures: $failures"

exit $failures
