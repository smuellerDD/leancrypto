if get_option('bike_5').enabled()
	bike_5_tester = executable('bike_5_tester',
				[ 'bike_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
				], link_with: leancrypto_static_lib
				)

	test('BIKE 5 KEM', bike_5_tester, suite: regression)
endif

if get_option('bike_3').enabled()
	bike_3_tester = executable('bike_3_tester',
				[ 'bike_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_BIKE_TYPE_3'
				)

	test('BIKE 3 KEM', bike_3_tester, suite: regression)
endif

if get_option('bike_1').enabled()
	bike_1_tester = executable('bike_1_tester',
				[ 'bike_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_BIKE_TYPE_1'
				)

	test('BIKE 1 KEM', bike_1_tester, suite: regression)
endif
