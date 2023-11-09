kyber_conf_data = configuration_data()
kyber_conf_data.set('kyber_strength', get_option('kyber_strength'))
kyber_conf_data.set('LC_KYBER_DOUBLE_KEM', true)
include_files += configure_file(input: 'lc_kyber.h.in', output: 'lc_kyber.h',
				configuration: kyber_conf_data)
