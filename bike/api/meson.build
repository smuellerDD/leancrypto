if get_option('bike_5').enabled()
	bike_5_conf_data = configuration_data()
	bike_5_conf_data.set('bike_strength', '5')
	bike_5_conf_data.set('bike_name', 'lc_bike_5')
	bike_5_conf_data.set('bike_header', '5_')
	include_files += configure_file(input: 'lc_bike_size.h.in',
					output: 'lc_bike_5.h',
					configuration: bike_5_conf_data)
endif

if get_option('bike_3').enabled()
	bike_3_conf_data = configuration_data()
	bike_3_conf_data.set('bike_strength', '3')
	bike_3_conf_data.set('bike_name', 'lc_bike_3')
	bike_3_conf_data.set('bike_header', '3_')
	include_files += configure_file(input: 'lc_bike_size.h.in',
					output: 'lc_bike_3.h',
					configuration: bike_3_conf_data)

endif

if get_option('bike_1').enabled()
	bike_1_conf_data = configuration_data()
	bike_1_conf_data.set('bike_strength', '1')
	bike_1_conf_data.set('bike_name', 'lc_bike_1')
	bike_1_conf_data.set('bike_header', '1_')
	include_files += configure_file(input: 'lc_bike_size.h.in',
					output: 'lc_bike_1.h',
					configuration: bike_1_conf_data)
endif

if (get_option('bike_5').enabled() or
    get_option('bike_3').enabled() or
    get_option('bike_1').enabled())
	include_files += files([ 'lc_bike.h' ])
endif
