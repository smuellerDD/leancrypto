if get_option('kyber_1024').enabled()
	kyber_conf_data = configuration_data()
	kyber_conf_data.set('kyber_strength', '4')
	kyber_conf_data.set('kyber_name', 'lc_kyber_1024')
	kyber_conf_data.set('kex_name', 'lc_kex_1024')
	kyber_conf_data.set('kyber_header', '1024_')
	kyber_conf_data.set('LC_KYBER_X25519_KEM',
			    get_option('kyber_x25519').enabled())
	kyber_conf_data.set('LC_KYBER_IES', aead_support_enabled == 1)
	include_files += configure_file(input: 'lc_kyber_size.h.in',
					output: 'lc_kyber_1024.h',
					configuration: kyber_conf_data)
endif

if get_option('kyber_768').enabled()
	kyber_768_conf_data = configuration_data()
	kyber_768_conf_data.set('kyber_strength', '3')
	kyber_768_conf_data.set('kyber_name', 'lc_kyber_768')
	kyber_768_conf_data.set('kex_name', 'lc_kex_768')
	kyber_768_conf_data.set('kyber_header', '768_')
	kyber_768_conf_data.set('LC_KYBER_X25519_KEM',
				get_option('kyber_x25519').enabled())
	kyber_768_conf_data.set('LC_KYBER_IES', aead_support_enabled == 1)
	include_files += configure_file(input: 'lc_kyber_size.h.in',
					output: 'lc_kyber_768.h',
					configuration: kyber_768_conf_data)

endif

if get_option('kyber_512').enabled()
	kyber_512_conf_data = configuration_data()
	kyber_512_conf_data.set('kyber_strength', '2')
	kyber_512_conf_data.set('kyber_name', 'lc_kyber_512')
	kyber_512_conf_data.set('kex_name', 'lc_kex_512')
	kyber_512_conf_data.set('kyber_header', '512_')
	kyber_512_conf_data.set('LC_KYBER_X25519_KEM',
				get_option('kyber_x25519').enabled())
	kyber_512_conf_data.set('LC_KYBER_IES', aead_support_enabled == 1)
	include_files += configure_file(input: 'lc_kyber_size.h.in',
					output: 'lc_kyber_512.h',
					configuration: kyber_512_conf_data)
endif

include_files += files([ 'lc_kyber.h' ])
