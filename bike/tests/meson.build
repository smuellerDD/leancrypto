	bike_tester = executable('bike_tester',
				[ 'bike_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
				], link_with: leancrypto_static_lib
				)

	test('BIKE KEM', bike_tester, suite: regression)
