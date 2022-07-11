# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('chacha20_drng').enabled()
	src += files([ 'chacha20_drng.c' ])
endif

if get_option('kmac_drng').enabled()
	src += files([ 'kmac_drng.c' ])
endif

if get_option('cshake_drng').enabled()
	src += files([ 'cshake_drng.c' ])
endif

if get_option('drbg_hash').enabled() or get_option('drbg_hmac').enabled()
	src += files([ 'drbg.c' ])
endif

if get_option('drbg_hash').enabled()
	src += files([ 'hash_drbg.c' ])
endif

if get_option('drbg_hmac').enabled()
	src += files([ 'hmac_drbg.c' ])
endif
