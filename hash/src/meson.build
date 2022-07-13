# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_hash = 0

if get_option('sha2-256').enabled()
	src += files([ 'sha256.c' ])
	include_files += files([ '../api/lc_sha256.h' ])
	lc_hash = 1
endif

if get_option('sha2-512').enabled()
	src += files([ 'sha512.c' ])
	include_files += files([ '../api/lc_sha512.h' ])
	lc_hash = 1
endif

if get_option('sha3').enabled()
	src += files([ 'cshake.c', 'sha3.c' ])
	include_files += files([ '../api/lc_cshake.h', '../api/lc_sha3.h' ])
	lc_hash = 1
endif

if (lc_hash == 1)
	src += files([ 'hash.c' ])
	include_files += files([ '../api/lc_hash.h' ])
endif
