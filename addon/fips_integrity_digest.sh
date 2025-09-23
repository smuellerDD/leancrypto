#!/bin/bash

#
# Tool to extract the message digest of the FIPS library. This digest provides
# an unambiguous reference that can be added to a FIPS Security Policy
# to refer to the library version.
#
# Invocation:
#	$0 <libleancrypto-fips.so>
#
# The returned data is the message digest that is applied by the integrity
# check, typically a SHA3-256 digest.
#

SOFILE="$1"

FIPSDATASEGMENT=".lc_fips_integrity_data"
SECOUTFILE="extracted_sections.digest"

OBJCOPY="objcopy"
XXD="xxd"

################################################################################

if [ -z "$SOFILE" -o ! -f "$SOFILE" ]
then
	echo "ERROR: shared library file $SOFILE not found"
	exit 1
fi

trap "rm -f $FIPSDATASEGMENT.$$" 0 1 2 15

# Extract section with digest
$OBJCOPY							\
 --dump-section $FIPSDATASEGMENT=$FIPSDATASEGMENT.$$		\
 $SOFILE
if [ $? -ne 0 ]
then
	echo "ERROR: $OBJCOPY command failed: $?"
	exit $?
fi

# Print out the hex string
$XXD -p $FIPSDATASEGMENT.$$ | sed -e 's/../:&/2g'
