# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('hash_crypt').enabled()
	src += files([
		'cshake_crypt.c',
		'hash_crypt.c',
		'kmac_crypt.c',
	])

	include_files += files([
		'../api/lc_aead.h',
		'../api/lc_cshake_crypt.h',
		'../api/lc_hash_crypt.h',
		'../api/lc_kmac_crypt.h'
	])
endif
