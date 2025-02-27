#!/bin/bash
set -x
CMD=$1
shift
OUTFILE=$1
shift

$CMD > /dev/null 2>$OUTFILE.$$
if [ $? -eq 1 ]
then
	mv -f $OUTFILE.$$ $OUTFILE
else
	rm -f $OUTFILE.$$
fi
exit 0
