# for i in $(ls *.c | sort); do echo "'$i',"; done
bike_c = files([
	'bike_decode.c',
	'bike_decode_portable.c',
	'bike_gf2x_inv.c',
	'bike_gf2x_ksqr_portable.c',
	'bike_gf2x_mul.c',
	'bike_gf2x_mul_base_portable.c',
	'bike_gf2x_mul_portable.c',
	'bike_kem.c',
	'bike_sampling.c',
	'bike_sampling_portable.c',
])

if get_option('bike_5').enabled()
	bike_5_files = bike_c

	leancrypto_bike_5_c_lib = static_library(
		'leancrypto_bike_5_c_lib',
		[ bike_5_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
	)
	leancrypto_support_libs += leancrypto_bike_5_c_lib
endif

if get_option('bike_3').enabled()
	bike_3_files = bike_c

	leancrypto_bike_3_c_lib = static_library(
		'leancrypto_bike_3_c_lib',
		[ bike_3_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_BIKE_TYPE_3'
	)
	leancrypto_support_libs += leancrypto_bike_3_c_lib
endif

if get_option('bike_1').enabled()
	bike_1_files = bike_c

	leancrypto_bike_1_c_lib = static_library(
		'leancrypto_bike_1_c_lib',
		[ bike_1_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_BIKE_TYPE_1'
	)
	leancrypto_support_libs += leancrypto_bike_1_c_lib
endif
