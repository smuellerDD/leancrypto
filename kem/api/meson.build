kyber_conf_data = configuration_data()
kyber_conf_data.set('kyber_strength', get_option('kyber_strength'))
include_files += configure_file(input: 'lc_kyber.h.in', output: 'lc_kyber.h',
				configuration: kyber_conf_data)
