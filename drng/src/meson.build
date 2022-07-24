# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_rng_header = 0

if get_option('chacha20_drng').enabled()
	src += files([ 'chacha20_drng.c' ])
	include_files += files([ '../api/lc_chacha20_drng.h' ])
	lc_rng_header = 1
endif

if get_option('kmac_drng').enabled()
	src += files([ 'kmac_drng.c' ])
	include_files += files([ '../api/lc_kmac256_drng.h' ])
	lc_rng_header = 1
endif

if get_option('cshake_drng').enabled()
	src += files([ 'cshake_drng.c' ])
	include_files += files([ '../api/lc_cshake256_drng.h' ])
	lc_rng_header = 1
endif

if get_option('drbg_hash').enabled()
	src += files([ 'hash_drbg.c' ])
	include_files += files([ '../api/lc_hash_drbg.h' ])
	lc_rng_header = 1
endif

if get_option('drbg_hmac').enabled()
	src += files([ 'hmac_drbg.c' ])
	include_files += files([ '../api/lc_hmac_drbg.h',
				 '../api/lc_hmac_drbg_sha512.h' ])
	lc_rng_header = 1
endif

if get_option('drbg_hash').enabled() or get_option('drbg_hmac').enabled()
	include_files += files([ '../api/lc_drbg.h' ])
endif

if (lc_rng_header == 1)
	include_files += files([ '../api/lc_rng.h' ])
endif
