include_bike_internal = include_directories([ '../src' ])

bike_tests_generic = false

if get_option('bike_5').enabled()
	bike_tests_generic = true

	bike_5_tester = executable('bike_5_tester',
				[ 'bike_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_bike_internal
				], link_with: leancrypto_static_lib
				)
	bike_5_tester_perf = executable('bike_5_tester_perf',
				[ 'bike_tester_perf.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_bike_internal
				], link_with: leancrypto_static_lib
				)

	test('BIKE 5 KEM Common', bike_5_tester, suite: regression)
	test('BIKE 5 KEM C', bike_5_tester, args : [ 'c' ], suite: regression,
	     timeout: 300)

	test('BIKE 5 KEM 200 Common', bike_5_tester_perf, timeout: 1000,
	     is_parallel: false, suite: performance)
	test('BIKE 5 KEM 200 C', bike_5_tester_perf, args : [ 'c' ], timeout: 1000,
	     is_parallel: false, suite: performance)
endif

if get_option('bike_3').enabled()
	bike_tests_generic = true

	bike_3_tester = executable('bike_3_tester',
				[ 'bike_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_bike_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_BIKE_TYPE_3'
				)
	bike_3_tester_perf = executable('bike_3_tester_perf',
				[ 'bike_tester_perf.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_bike_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_BIKE_TYPE_3'
				)

	test('BIKE 3 KEM Common', bike_3_tester, suite: regression)
	test('BIKE 3 KEM C', bike_3_tester, args : [ 'c' ], suite: regression,
	     timeout: 300)

	test('BIKE 3 KEM 200 Common', bike_3_tester_perf, timeout: 1000,
	     is_parallel: false, suite: performance)
	test('BIKE 3 KEM 200 C', bike_3_tester_perf, args : [ 'c' ], timeout: 1000,
	     is_parallel: false, suite: performance)
endif

if get_option('bike_1').enabled()
	bike_tests_generic = true

	bike_1_tester = executable('bike_1_tester',
				[ 'bike_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_bike_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_BIKE_TYPE_1'
				)
	bike_1_tester_perf = executable('bike_1_tester_perf',
				[ 'bike_tester_perf.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_bike_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_BIKE_TYPE_1'
				)

	test('BIKE 1 KEM Common', bike_1_tester, suite: regression)
	test('BIKE 1 KEM C', bike_1_tester, args : [ 'c' ], suite: regression,
	     timeout: 300)

	test('BIKE 1 KEM 200 Common', bike_1_tester_perf, timeout: 1000,
	     is_parallel: false, suite: performance)
	test('BIKE 1 KEM 200 C', bike_1_tester_perf, args : [ 'c' ], timeout: 1000,
	     is_parallel: false, suite: performance)
endif

if bike_tests_generic
	bike_kem_official_tester = executable('bike_kem_official_tester',
				[ 'bike_kem_official_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_bike_internal
				], link_with: leancrypto_lib
				)
	test('BIKE official API KEM', bike_kem_official_tester,
	     suite: regression)
endif
