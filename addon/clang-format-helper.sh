#!/bin/bash

#
# Helper script to invoke clang-format to re-format all files allowed to be
# touched by clang-format.
#

# Files to exclude from formatting
# Make sure the file is provided with the exact string as the find command below
# will report it!
EXCLUDE="./internal/api/assembler_support.h"

# Clang-format tool
CLANGFORMAT="clang-format"
CLANGCONF="./.clang-format"

files="$(find ./ -name *.c)"
files="$files $(find ./ -name *.h)"

if [ ! -f "$CLANGCONF" ]
then
	echo "clang-format configuration file $CLANGCONF not found"
	exit 1
fi

for i in $EXCLUDE
do
	files=$(echo $files | sed "s!$i!!g")
done

$CLANGFORMAT -i $files
