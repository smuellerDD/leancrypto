if get_option('sntrup_1277').enabled()
	sntrup_1277_conf_data = configuration_data()
	sntrup_1277_conf_data.set('sntrup_mode', '1277')
	sntrup_1277_conf_data.set('sntrup_name', 'lc_sntrup_1277')
	sntrup_1277_conf_data.set('sntrup_header', 'SNTRUP_1277_')
	include_files += configure_file(input: 'lc_sntrup_size.h.in',
					output: 'lc_sntrup_1277.h',
					configuration: sntrup_1277_conf_data)
endif

if get_option('sntrup_1013').enabled()
	sntrup_1013_conf_data = configuration_data()
	sntrup_1013_conf_data.set('sntrup_mode', '1013')
	sntrup_1013_conf_data.set('sntrup_name', 'lc_sntrup_1013')
	sntrup_1013_conf_data.set('sntrup_header', 'SNTRUP_1013_')
	include_files += configure_file(input: 'lc_sntrup_size.h.in',
					output: 'lc_sntrup_1013.h',
					configuration: sntrup_1013_conf_data)
endif

if get_option('sntrup_953').enabled()
	sntrup_953_conf_data = configuration_data()
	sntrup_953_conf_data.set('sntrup_mode', '953')
	sntrup_953_conf_data.set('sntrup_name', 'lc_sntrup_953')
	sntrup_953_conf_data.set('sntrup_header', 'SNTRUP_953_')
	include_files += configure_file(input: 'lc_sntrup_size.h.in',
					output: 'lc_sntrup_953.h',
					configuration: sntrup_953_conf_data)
endif

if get_option('sntrup_857').enabled()
	sntrup_857_conf_data = configuration_data()
	sntrup_857_conf_data.set('sntrup_mode', '857')
	sntrup_857_conf_data.set('sntrup_name', 'lc_sntrup_857')
	sntrup_857_conf_data.set('sntrup_header', 'SNTRUP_857_')
	include_files += configure_file(input: 'lc_sntrup_size.h.in',
					output: 'lc_sntrup_857.h',
					configuration: sntrup_857_conf_data)
endif

if get_option('sntrup_761').enabled()
	sntrup_761_conf_data = configuration_data()
	sntrup_761_conf_data.set('sntrup_mode', '761')
	sntrup_761_conf_data.set('sntrup_name', 'lc_sntrup_761')
	sntrup_761_conf_data.set('sntrup_header', 'SNTRUP_761_')
	include_files += configure_file(input: 'lc_sntrup_size.h.in',
					output: 'lc_sntrup_761.h',
					configuration: sntrup_761_conf_data)
endif

include_files += files([ 'lc_sntrup.h' ])
