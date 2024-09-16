if get_option('dilithium_87').enabled()
	dilithium_conf_data = configuration_data()
	dilithium_conf_data.set('dilithium_strength', '5')
	dilithium_conf_data.set('dilithium_name', 'lc_dilithium_87')
	dilithium_conf_data.set('dilithium_macro', 'LC_DILITHIUM_87')
	dilithium_conf_data.set('dilithium_header', '87_')
	dilithium_conf_data.set('LC_DILITHIUM_ED25519_SIG',
				get_option('dilithium_ed25519').enabled())
	include_files += configure_file(input: 'lc_dilithium_size.h.in',
					output: 'lc_dilithium_87.h',
					configuration: dilithium_conf_data)
endif

if get_option('dilithium_65').enabled()
	dilithium_65_conf_data = configuration_data()
	dilithium_65_conf_data.set('dilithium_strength', '3')
	dilithium_65_conf_data.set('dilithium_name', 'lc_dilithium_65')
	dilithium_65_conf_data.set('dilithium_macro', 'LC_DILITHIUM_65')
	dilithium_65_conf_data.set('dilithium_header', '65_')
	dilithium_65_conf_data.set('LC_DILITHIUM_ED25519_SIG',
				get_option('dilithium_ed25519').enabled())
	include_files += configure_file(input: 'lc_dilithium_size.h.in',
					output: 'lc_dilithium_65.h',
					configuration: dilithium_65_conf_data)

endif

if get_option('dilithium_44').enabled()
	dilithium_44_conf_data = configuration_data()
	dilithium_44_conf_data.set('dilithium_strength', '2')
	dilithium_44_conf_data.set('dilithium_name', 'lc_dilithium_44')
	dilithium_44_conf_data.set('dilithium_macro', 'LC_DILITHIUM_44')
	dilithium_44_conf_data.set('dilithium_header', '44_')
	dilithium_44_conf_data.set('LC_DILITHIUM_ED25519_SIG',
				get_option('dilithium_ed25519').enabled())
	include_files += configure_file(input: 'lc_dilithium_size.h.in',
					output: 'lc_dilithium_44.h',
					configuration: dilithium_44_conf_data)
endif

include_files += files([ 'lc_dilithium.h' ])
