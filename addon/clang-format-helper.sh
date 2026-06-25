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

files="$(find ./ -name *.c -type f)"
files="$files $(find ./ -name *.h -type f)"

if [ ! -f "$CLANGCONF" ]
then
	echo "clang-format configuration file $CLANGCONF not found"
	exit 1
fi
if [ ! -f "$CLANGFORMAT" ]
then
	CLANGFORMAT="$CLANGFORMAT-22"
fi

for i in $EXCLUDE
do
	files=$(echo $files | sed "s!$i!!g")
done

$CLANGFORMAT -i $files

# Rust format tool
RUSTFORMAT="rustfmt"
RUSTCONF="./.rustfmt.toml"
files="$(find ./rust/src -name *.rs -type f)"
files="$files $(find ./rust/examples -name *.rs -type f)"
files="$files $(find ./rust/tests -name *.rs -type f)"
files="$files $(find ./rustls/src -name *.rs -type f)"
files="$files $(find ./rustls/tests -name *.rs -type f)"

if [ ! -f "$RUSTCONF" ]
then
	echo "$RUSTFORMAT configuration file $RUSTCONF not found"
	exit 1
fi

$RUSTFORMAT $files
