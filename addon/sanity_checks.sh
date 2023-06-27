#!/bin/bash

CHANGESFILE="CHANGES.md"


if [ ! -d "$MESON_SOURCE_ROOT" ]
then
	echo "Source directory not found"
	exit 1
fi

VERSION=$1
if [ -z "$VERSION" ]
then
	echo "Version missing"
	exit 1
fi

check_git_blockchain() {
	git fsck --full --strict
	local ret=$?

	if [ $ret -ne 0 ]
	then
		exit $ret
	fi
}

# Check that there all changes are checked in
require_clean_work_tree() {
	git gc --aggressive -q

	# Update the index
	git update-index -q --ignore-submodules --refresh
	local err=0

	# Disallow unstaged changes in the working tree
	if ! git diff-files --quiet --ignore-submodules --
	then
		echo >&2 "cannot $1: you have unstaged changes."
		git diff-files --name-status -r --ignore-submodules -- >&2
		err=1
	fi

	# Disallow uncommitted changes in the index
	if ! git diff-index --cached --quiet HEAD --ignore-submodules --
	then
		echo >&2 "cannot $1: your index contains uncommitted changes."
		git diff-index --cached --name-status -r --ignore-submodules HEAD -- >&2
		err=1
	fi

	if [ $err = 1 ]
	then
		echo >&2 "Please commit or stash them."
		exit 1
	fi
}

check_copyright_date() {
	local file=$1
	local year=$(date "+%Y")
	local numentries=0
	local searchyear
	local newyear

	if [ ! -f $file ]
	then
		return
	fi

	local fileyear=$(grep "Copyright" $file | grep "Stephan" | grep -o -E '[0-9]+')
	if [ -z "$fileyear" ]
	then
		return
	fi

	for i in $fileyear
	do
		numentries=$((numentries+1))
		searchyear=$i
	done

	if [ $numentries -gt 2 ]
	then
		return
	fi

	if [ $numentries -eq 1 ]
	then
		if [ x"$year" = x"$searchyear" ]
		then
			return
		fi
		newyear="$searchyear - $year"
	else
		if [ x"$year" = x"$searchyear" ]
		then
			return
		fi

		newyear="$year"
	fi

	sed -i "/Copyright/s/$searchyear/$newyear/" $file
}

# Cleanup code base
# $1 repository destination
# $@ skipped destinations
code_cleanup() {
	local targetdir=$1
	shift

	for i in $(find $targetdir -type f)
	do

		skip=0

		for j in $@
		do
			if (echo $i | grep -q $j)
			then
				skip=1
				break
			fi
		done

		if [ $skip -eq 0 ]
		then
			check_copyright_date $i
		fi
	done
}

# Check for a clean code using cppcheck
# $@ files to check
check_codesanity() {
	local res=$(cppcheck -q --enable=performance --enable=warning --enable=portability $@ 2>/dev/null)

	if [ -n "$res" ]
	then
		echo "cppcheck returned with data -- please check" >&2
		exit 1
	fi
}

# Sanity Checks
check_existence() {
	local file=$1
	if [ ! -f $file ]
	then
		echo "$1 file not present" >&2
		exit 1
	fi
}

# Check for a clean repository
# $1 Version number
check_reposanity() {
	local version=$1

	check_existence ${CHANGESFILE}
	check_existence README.md
	if ! $(head -n1 ${CHANGESFILE} | grep -q "$version" )
	then
		#git log --pretty=format"%h %an %s" ${OLDVER}..HEAD
		echo "Forgot to add $version changes to ${CHANGESFILE}" >&2
		exit 1
	fi

	if $(head -n1 ${CHANGESFILE} | grep -q "prerelease" )
	then
		echo "Preliminary release - skipping full release validation" >&2
		exit 0
	fi
}

# Check that only signed commits are present
check_only_signed_commits() {
	# Git preparation
	local oldver=$(git tag --sort="v:refname" | tail -n1)

	# Check for only signed check-ins since old release
	if [ "$(git log --pretty=%G? ${oldver}..HEAD | grep -v G)" != "" ]
	then
		echo "ERROR: Unsigned check-ins found" >&2
		exit 1
	fi
}

# Tag the tree
# $1 Name of the project
# $2 Version of the project
tag()
{
	local name=$1
	local version=$2

	echo "Setting tag v${version}" >&2
	git tag -s -m "Release $name-$version" "v${version}" >&2 || exit 1
}

# Push it to its remote trees
# $1 Name of the project
# $2 Version of the project
push() {
	for i in $(git remote -v | grep push  | cut -f1)
	do
		echo "Pushing to remote repository $i" >&2
		git push --tags -u $i master
	done
}

# Prepare GIT repo for a complete new release
# $1 location of git repo
# $2 version of source
# return: version number
prepare_gitrepo() {
	local target=$1
	local version=$2
	local nopush=$3

	local version
	local dir=$(pwd)

	if [ -d $target ]
	then
		cd $target
	fi

	check_reposanity $version
	[ $? -ne 0 ] && exit 1

	code_cleanup $(pwd) ".git" build $0
	[ $? -ne 0 ] && exit 1

	check_only_signed_commits
	[ $? -ne 0 ] && exit 1

	require_clean_work_tree
	[ $? -ne 0 ] && exit 1

	check_git_blockchain
	[ $? -ne 0 ] && exit 1

	tag $(basename $(pwd)) $version
	[ $? -ne 0 ] && exit 1

	if [ -z "$nopush" ]
	then
		push
		[ $? -ne 0 ] && exit 1
	fi

	cd $dir
}

prepare_gitrepo $MESON_SOURCE_ROOT $VERSION
