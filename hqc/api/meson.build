if get_option('hqc_256').enabled()
	hqc_256_conf_data = configuration_data()
	hqc_256_conf_data.set('hqc_strength', '256')
	hqc_256_conf_data.set('hqc_name', 'lc_hqc_256')
	hqc_256_conf_data.set('hqc_header', '256_')
	include_files += configure_file(input: 'lc_hqc_size.h.in',
					output: 'lc_hqc_256.h',
					configuration: hqc_256_conf_data)
endif

if get_option('hqc_192').enabled()
	hqc_192_conf_data = configuration_data()
	hqc_192_conf_data.set('hqc_strength', '192')
	hqc_192_conf_data.set('hqc_name', 'lc_hqc_192')
	hqc_192_conf_data.set('hqc_header', '192_')
	include_files += configure_file(input: 'lc_hqc_size.h.in',
					output: 'lc_hqc_192.h',
					configuration: hqc_192_conf_data)
endif

if get_option('hqc_128').enabled()
	hqc_128_conf_data = configuration_data()
	hqc_128_conf_data.set('hqc_strength', '128')
	hqc_128_conf_data.set('hqc_name', 'lc_hqc_128')
	hqc_128_conf_data.set('hqc_header', '128_')
	include_files += configure_file(input: 'lc_hqc_size.h.in',
					output: 'lc_hqc_128.h',
					configuration: hqc_128_conf_data)
endif

include_files += files([ 'lc_hqc.h' ])
