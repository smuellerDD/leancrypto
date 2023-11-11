dilithium_conf_data = configuration_data()
dilithium_conf_data.set('dilithium_strength', get_option('dilithium_strength'))
dilithium_conf_data.set('LC_DILITHIUM_ED25519_SIG',
			get_option('dilithium_ed25519').enabled())
include_files += configure_file(input: 'lc_dilithium.h.in',
				output: 'lc_dilithium.h',
				configuration: dilithium_conf_data)
