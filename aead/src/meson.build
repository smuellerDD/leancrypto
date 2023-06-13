# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('hash_crypt').enabled()
	src += files([
		'cshake_crypt.c',
		'hash_crypt.c',
		'kmac_crypt.c'
	])

	include_files += files([
		'../api/lc_aead.h',
		'../api/lc_cshake_crypt.h',
		'../api/lc_hash_crypt.h',
		'../api/lc_kmac_crypt.h',
	])
endif

# We need HMAC and a symmetric algo
if (get_option('aes_cbc').enabled() or get_option('aes_ctr').enabled())
	if get_option('sha2-512').enabled()
		src += files([
			'symhmac.c'
		])

		include_files += files([
			'../api/lc_symhmac.h'
		])
	endif

	if get_option('kmac').enabled()
		src += files([
			'symkmac.c'
		])

		include_files += files([
			'../api/lc_symkmac.h'
		])
	endif
endif
