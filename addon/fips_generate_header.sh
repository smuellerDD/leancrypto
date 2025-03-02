#!/bin/bash
set -x
CMD=$1
shift
OUTFILE=$1
shift

echo "__attribute__ ((section(\"fips_integrity_data\")))" > $OUTFILE.$$
echo "static const uint8_t expected_digest[] = {" >> $OUTFILE.$$
$CMD > /dev/null 2>>$OUTFILE.$$
ret=$?
echo "};" >> $OUTFILE.$$
if [ $ret -eq 1 ]
then
	mv -f $OUTFILE.$$ $OUTFILE
else
	rm -f $OUTFILE.$$
fi
exit 0
