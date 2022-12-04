# for i in $(ls *.c | sort); do echo "'$i',"; done

src += files([
	'hmac.c',
])

include_files += files([ '../api/lc_hmac.h' ])

hash_present = 0

if get_option('sha2-256').enabled()
	src += files([ 'hmac_sha256_selftest.c' ])
	hash_present = 1
else
	src += files([ 'hmac_sha256_selftest_null.c' ])
endif

if (hash_present == 0 and get_option('sha2-512').enabled())
	src += files([ 'hmac_sha512_selftest.c' ])
	hash_present = 1
else
	src += files([ 'hmac_sha512_selftest_null.c' ])
endif

if (hash_present == 0 and get_option('sha3').enabled())
	src += files([ 'hmac_sha3_selftest.c' ])
	hash_present = 1
else
	src += files([ 'hmac_sha3_selftest_null.c' ])
endif
