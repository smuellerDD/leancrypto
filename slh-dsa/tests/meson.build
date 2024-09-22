if get_option('sphincs_shake_256s').enabled()
	include_sphincs_internal = include_directories([ '../src' ])

	sphincs_tester_256s_c = executable('sphincs_tester_256s_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				link_with: leancrypto_static_lib
				)
	sphincs_tester_256f_c = executable('sphincs_tester_256f_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_256F',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_192s_c = executable('sphincs_tester_192s_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_192S',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_192f_c = executable('sphincs_tester_192f_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_192F',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_128s_c = executable('sphincs_tester_128s_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_128S',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_128f_c = executable('sphincs_tester_128f_c',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_128F',
				link_with: leancrypto_static_lib
				)

	test('Sphincs SHAKE 256s Accel', sphincs_tester_256s_c, suite: regression)
	test('Sphincs SHAKE 256f Accel', sphincs_tester_256f_c, suite: regression)
	test('Sphincs SHAKE 192s Accel', sphincs_tester_192s_c, suite: regression)
	test('Sphincs SHAKE 192f Accel', sphincs_tester_192f_c, suite: regression)
	test('Sphincs SHAKE 128s Accel', sphincs_tester_128s_c, suite: regression)
	test('Sphincs SHAKE 128f Accel', sphincs_tester_128f_c, suite: regression)

	test('Sphincs SHAKE 256s Keygen 100 Accel', sphincs_tester_256s_c,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Keygen 100 Accel', sphincs_tester_256f_c,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Keygen 100 Accel', sphincs_tester_192s_c,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Keygen 100 Accel', sphincs_tester_192f_c,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Keygen 100 Accel', sphincs_tester_128s_c,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Keygen 100 Accel', sphincs_tester_128f_c,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Sign 10 Accel', sphincs_tester_256s_c,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Sign 10 Accel', sphincs_tester_256f_c,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Sign 10 Accel', sphincs_tester_192s_c,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Sign 10 Accel', sphincs_tester_192f_c,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Sign 10 Accel', sphincs_tester_128s_c,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Sign 10 Accel', sphincs_tester_128f_c,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Verify 1000 Accel', sphincs_tester_256s_c,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Verify 1000 Accel', sphincs_tester_256f_c,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Verify 1000 Accel', sphincs_tester_192s_c,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Verify 1000 Accel', sphincs_tester_192f_c,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Verify 1000 Accel', sphincs_tester_128s_c,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Verify 1000 Accel', sphincs_tester_128f_c,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s C', sphincs_tester_256s_c, args : [ 'c' ],
	     suite: regression)
	test('Sphincs SHAKE 256f C', sphincs_tester_256f_c, args : [ 'c' ],
	     suite: regression)
	test('Sphincs SHAKE 192s C', sphincs_tester_192s_c, args : [ 'c' ],
	     suite: regression)
	test('Sphincs SHAKE 192f C', sphincs_tester_192f_c, args : [ 'c' ],
	     suite: regression)
	test('Sphincs SHAKE 128s C', sphincs_tester_128s_c, args : [ 'c' ],
	     suite: regression)
	test('Sphincs SHAKE 128f C', sphincs_tester_128f_c, args : [ 'c' ],
	     suite: regression)

	test('Sphincs SHAKE 256s Keygen 100 C', sphincs_tester_256s_c,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Keygen 100 C', sphincs_tester_256f_c,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Keygen 100 C', sphincs_tester_192s_c,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Keygen 100 C', sphincs_tester_192f_c,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Keygen 100 C', sphincs_tester_128s_c,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Keygen 100 C', sphincs_tester_128f_c,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Sign 10 C', sphincs_tester_256s_c,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Sign 10 C', sphincs_tester_256f_c,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Sign 10 C', sphincs_tester_192s_c,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Sign 10 C', sphincs_tester_192f_c,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Sign 10 C', sphincs_tester_128s_c,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Sign 10 C', sphincs_tester_128f_c,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Verify 1000 C', sphincs_tester_256s_c,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Verify 1000 C', sphincs_tester_256f_c,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Verify 1000 C', sphincs_tester_192s_c,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Verify 1000 C', sphincs_tester_192f_c,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Verify 1000 C', sphincs_tester_128s_c,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Verify 1000 C', sphincs_tester_128f_c,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
endif
