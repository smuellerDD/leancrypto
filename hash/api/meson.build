hash_conf_data = configuration_data()
if x86_64_asm and get_option('ascon').enabled()
	hash_conf_data.set('hash_common_alignment', 64)
elif arm32_neon_gcc_asm
	hash_conf_data.set('hash_common_alignment', 32)
else
	hash_conf_data.set('hash_common_alignment', 8)
endif
include_files += configure_file(input: 'lc_hash.h.in',
				output: 'lc_hash.h',
				configuration: hash_conf_data)

ascon_hash_conf_data = configuration_data()
ascon_hash_conf_data.set('LC_DEF_ASCON_AVX512',
			(x86_64_asm and get_option('ascon').enabled()))
include_files += configure_file(input: 'lc_ascon_hash.h.in',
				output: 'lc_ascon_hash.h',
				configuration: ascon_hash_conf_data)
