if get_option('sphincs_shake_256s').enabled()
	sphincs_shake_256s_conf_data = configuration_data()
	sphincs_shake_256s_conf_data.set('sphincs_strength', '29792')
	sphincs_shake_256s_conf_data.set('sphincs_name', 'lc_sphincs_shake_256s')
	sphincs_shake_256s_conf_data.set('sphincs_header', 'SHAKE_256S_')
	include_files += configure_file(input: 'lc_sphincs_size.h.in',
					output: 'lc_sphincs_shake_256s.h',
					configuration: sphincs_shake_256s_conf_data)
endif

if get_option('sphincs_shake_256f').enabled()
	sphincs_shake_256f_conf_data = configuration_data()
	sphincs_shake_256f_conf_data.set('sphincs_strength', '49856')
	sphincs_shake_256f_conf_data.set('sphincs_name', 'lc_sphincs_shake_256f')
	sphincs_shake_256f_conf_data.set('sphincs_header', 'SHAKE_256F_')
	include_files += configure_file(input: 'lc_sphincs_size.h.in',
					output: 'lc_sphincs_shake_256f.h',
					configuration: sphincs_shake_256f_conf_data)
endif

if get_option('sphincs_shake_192s').enabled()
	sphincs_shake_192s_conf_data = configuration_data()
	sphincs_shake_192s_conf_data.set('sphincs_strength', '16224')
	sphincs_shake_192s_conf_data.set('sphincs_name', 'lc_sphincs_shake_192s')
	sphincs_shake_192s_conf_data.set('sphincs_header', 'SHAKE_192S_')
	include_files += configure_file(input: 'lc_sphincs_size.h.in',
					output: 'lc_sphincs_shake_192s.h',
					configuration: sphincs_shake_192s_conf_data)
endif

if get_option('sphincs_shake_192f').enabled()
	sphincs_shake_192f_conf_data = configuration_data()
	sphincs_shake_192f_conf_data.set('sphincs_strength', '35664')
	sphincs_shake_192f_conf_data.set('sphincs_name', 'lc_sphincs_shake_192f')
	sphincs_shake_192f_conf_data.set('sphincs_header', 'SHAKE_192F_')
	include_files += configure_file(input: 'lc_sphincs_size.h.in',
					output: 'lc_sphincs_shake_192f.h',
					configuration: sphincs_shake_192f_conf_data)
endif

if get_option('sphincs_shake_128s').enabled()
	sphincs_shake_128s_conf_data = configuration_data()
	sphincs_shake_128s_conf_data.set('sphincs_strength', '7856')
	sphincs_shake_128s_conf_data.set('sphincs_name', 'lc_sphincs_shake_128s')
	sphincs_shake_128s_conf_data.set('sphincs_header', 'SHAKE_128S_')
	include_files += configure_file(input: 'lc_sphincs_size.h.in',
					output: 'lc_sphincs_shake_128s.h',
					configuration: sphincs_shake_128s_conf_data)
endif

if get_option('sphincs_shake_128f').enabled()
	sphincs_shake_128f_conf_data = configuration_data()
	sphincs_shake_128f_conf_data.set('sphincs_strength', '17088')
	sphincs_shake_128f_conf_data.set('sphincs_name', 'lc_sphincs_shake_128f')
	sphincs_shake_128f_conf_data.set('sphincs_header', 'SHAKE_128F_')
	include_files += configure_file(input: 'lc_sphincs_size.h.in',
					output: 'lc_sphincs_shake_128f.h',
					configuration: sphincs_shake_128f_conf_data)
endif

#include_files += files([ 'lc_sphincs.h' ])
