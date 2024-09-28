# for i in $(ls *.c | sort); do echo "'$i',"; done

# The selftest_rng is internal code to be used for testing only - it shall not
# export any APIs and thus must be compiled along with internal support files
internal_src += files([ 'selftest_rng.c', 'static_rng.c' ])

lc_rng_header = 0
seeded_rng = 0

conf_data = configuration_data()

if get_option('chacha20_drng').enabled()
	src += files([ 'chacha20_drng.c' ])
	include_files += files([ '../api/lc_chacha20_drng.h' ])
	conf_data.set('LC_DRNG_CC20', 1)
	# Currently not supported
	# seeded_rng = 1
	lc_rng_header = 1
endif

if get_option('kmac_drng').enabled()
	src += files([ 'kmac_drng.c' ])
	include_files += files([ '../api/lc_kmac256_drng.h' ])
	conf_data.set('LC_DRNG_KMAC', 1)
	seeded_rng = 1
	lc_rng_header = 1
endif

if get_option('cshake_drng').enabled()
	src += files([ 'cshake_drng.c' ])
	include_files += files([ '../api/lc_cshake256_drng.h' ])
	conf_data.set('LC_DRNG_CSHAKE', 1)
	seeded_rng = 1
	lc_rng_header = 1
endif

if get_option('xdrbg').enabled()
	src += files([ 'xdrbg.c' ])
	if get_option('sha3').enabled()
		src += files([ 'xdrbg256.c' ])
		conf_data.set('LC_DRNG_XDRBG256', 1)
	endif
	if get_option('ascon').enabled()
		src += files([ 'xdrbg128.c' ])
		conf_data.set('LC_DRNG_XDRBG128', 1)
	endif
	include_files += files([ '../api/lc_xdrbg.h' ])
	conf_data.set('LC_DRNG_XDRBG', 1)
	seeded_rng = 1
	lc_rng_header = 1
endif

if get_option('drbg_hash').enabled()
	src += files([ 'hash_drbg.c' ])
	include_files += files([ '../api/lc_hash_drbg.h' ])
	conf_data.set('LC_DRNG_HASH_DRBG', 1)
	seeded_rng = 1
	lc_rng_header = 1
endif

if get_option('drbg_hmac').enabled()
	src += files([ 'hmac_drbg.c' ])
	include_files += files([ '../api/lc_hmac_drbg.h',
				 '../api/lc_hmac_drbg_sha512.h' ])
	conf_data.set('LC_DRNG_HMAC_DRBG', 1)
	# Currently not supported
	# seeded_rng = 1
	lc_rng_header = 1
endif

if get_option('drbg_hash').enabled() or get_option('drbg_hmac').enabled()
	include_files += files([ '../api/lc_drbg.h' ])
endif

if (lc_rng_header == 1)
	include_files += files([ '../api/lc_rng.h' ])
	src += files([ 'rng_api.c' ])
endif

if (seeded_rng == 1)
	src += files([ 'seeded_rng.c' ])

	if get_option('seedsource') == 'esdm'
		src += files([ 'seeded_rng_esdm.c' ])
		#Not required due to runtime linking
		#leancrypto_link += cc.find_library( 'esdm_rpc_client',
		#				    required: true)
	else
		if (host_machine.system() == 'linux')
			src += files([ 'seeded_rng_linux.c' ])
		endif

		if ((host_machine.system() == 'dragonfly') or
		    (host_machine.system() == 'freebsd') or
		    (host_machine.system() == 'openbsd'))
			src += files([ 'seeded_rng_bsd.c' ])
		endif

		if (host_machine.system() == 'darwin')
			src += files([ 'seeded_rng_darwin.c' ])
		endif

		if (host_machine.system() == 'windows')
			src += files([ 'seeded_rng_windows.c' ])
			leancrypto_link += cc.find_library( 'bcrypt',
							    required: true)
		endif
	endif
endif

configure_file(output: 'lc_drng_config.h', configuration : conf_data)
