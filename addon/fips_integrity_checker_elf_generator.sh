#!/bin/bash

SOFILE="$1"
HASHER="$2"

TEXTSEGMENT=".text"
INITSEGMENT=".init"
RODATASEGMENT=".lc_fips_rodata"
FIPSDATASEGMENT=".lc_fips_integrity_data"
SECOUTFILE="extracted_sections.digest"

OBJCOPY="objcopy"
CAT="cat"
CUT="cut"

################################################################################

if [ -z "$SOFILE" -o ! -f "$SOFILE" ]
then
	echo "ERROR: shared library file $SOFILE not found"
	exit 1
fi

if [ -z "$HASHER" -o ! -x "$HASHER" ]
then
	echo "ERROR: hasher executable $HASHER not found"
	exit 1
fi

#
# Make sure the segment files exist
#
touch $TEXTSEGMENT
touch $INITSEGMENT
touch $RODATASEGMENT

#
# Order of segments as processed in fips_integrity_checker_elf.c:
# 1. text
# 2. init
# 3. rodata

# Extract sections
$OBJCOPY							\
 --dump-section $TEXTSEGMENT=$TEXTSEGMENT			\
 --dump-section $INITSEGMENT=$INITSEGMENT			\
 --dump-section $RODATASEGMENT=$RODATASEGMENT			\
 $SOFILE 2>/dev/null
if [ $? -ne 0 ]
then
	echo "ERROR: $OBJCOPY command failed: $?"
	exit $?
fi

# Merge sections into file and create digest
$CAT $TEXTSEGMENT $INITSEGMENT $RODATASEGMENT | $HASHER -b - > $SECOUTFILE 2>/dev/null
if [ $? -ne 0 ]
then
	echo "ERROR: $CAT command failed: $?"
	exit $?
fi

# Insert data into library file
$OBJCOPY --update-section $FIPSDATASEGMENT="$SECOUTFILE" $SOFILE
if [ $? -ne 0 ]
then
	echo "ERROR: $OBJCOPY command failed: $?"
	exit $?
fi
