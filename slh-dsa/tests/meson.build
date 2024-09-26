if get_option('sphincs_shake_256s').enabled()
	include_sphincs_internal = include_directories([ '../src' ])

	sphincs_tester_256s = executable('sphincs_tester_256s',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				link_with: leancrypto_static_lib
				)
	sphincs_tester_256f = executable('sphincs_tester_256f',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_256F',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_192s = executable('sphincs_tester_192s',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_192S',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_192f = executable('sphincs_tester_192f',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_192F',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_128s = executable('sphincs_tester_128s',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_128S',
				link_with: leancrypto_static_lib
				)
	sphincs_tester_128f = executable('sphincs_tester_128f',
				[ 'sphincs_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_sphincs_internal
				],
				c_args : '-DLC_SPHINCS_TYPE_128F',
				link_with: leancrypto_static_lib
				)
	sphincs_official_tester = executable('sphincs_official_tester',
				[ 'sphincs_official_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
				],
				dependencies: leancrypto
				)
	sphincs_iuf_tester = executable('sphincs_iuf_tester',
				[ 'sphincs_iuf_tester.c' ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
				],
				dependencies: leancrypto
				)

	test('Sphincs SHAKE 256s Accel', sphincs_tester_256s, suite: regression)
	test('Sphincs SHAKE 256f Accel', sphincs_tester_256f, suite: regression)
	test('Sphincs SHAKE 192s Accel', sphincs_tester_192s, suite: regression)
	test('Sphincs SHAKE 192f Accel', sphincs_tester_192f, suite: regression)
	test('Sphincs SHAKE 128s Accel', sphincs_tester_128s, suite: regression)
	test('Sphincs SHAKE 128f Accel', sphincs_tester_128f, suite: regression)

	test('Sphincs SHAKE 256s Keygen 100 Accel', sphincs_tester_256s,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Keygen 100 Accel', sphincs_tester_256f,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Keygen 100 Accel', sphincs_tester_192s,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Keygen 100 Accel', sphincs_tester_192f,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Keygen 100 Accel', sphincs_tester_128s,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Keygen 100 Accel', sphincs_tester_128f,
	     args : [ 'k' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Sign 10 Accel', sphincs_tester_256s,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Sign 10 Accel', sphincs_tester_256f,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Sign 10 Accel', sphincs_tester_192s,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Sign 10 Accel', sphincs_tester_192f,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Sign 10 Accel', sphincs_tester_128s,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Sign 10 Accel', sphincs_tester_128f,
	     args : [ 's' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Verify 1000 Accel', sphincs_tester_256s,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Verify 1000 Accel', sphincs_tester_256f,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Verify 1000 Accel', sphincs_tester_192s,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Verify 1000 Accel', sphincs_tester_192f,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Verify 1000 Accel', sphincs_tester_128s,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Verify 1000 Accel', sphincs_tester_128f,
	     args : [ 'v' ], timeout: 1000, is_parallel: false, suite: performance)

	# Disable parallel execution as accelerations are disabled
	test('Sphincs SHAKE 256s C', sphincs_tester_256s, args : [ 'c' ],
	     is_parallel: false, suite: regression)
	test('Sphincs SHAKE 256f C', sphincs_tester_256f, args : [ 'c' ],
	     is_parallel: false, suite: regression)
	test('Sphincs SHAKE 192s C', sphincs_tester_192s, args : [ 'c' ],
	     is_parallel: false, suite: regression)
	test('Sphincs SHAKE 192f C', sphincs_tester_192f, args : [ 'c' ],
	     is_parallel: false, suite: regression)
	test('Sphincs SHAKE 128s C', sphincs_tester_128s, args : [ 'c' ],
	     is_parallel: false, suite: regression)
	test('Sphincs SHAKE 128f C', sphincs_tester_128f, args : [ 'c' ],
	     is_parallel: false, suite: regression)

	test('Sphincs SHAKE 256s Keygen 100 C', sphincs_tester_256s,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Keygen 100 C', sphincs_tester_256f,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Keygen 100 C', sphincs_tester_192s,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Keygen 100 C', sphincs_tester_192f,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Keygen 100 C', sphincs_tester_128s,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Keygen 100 C', sphincs_tester_128f,
	     args : [ 'k', 'c' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Sign 10 C', sphincs_tester_256s,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Sign 10 C', sphincs_tester_256f,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Sign 10 C', sphincs_tester_192s,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Sign 10 C', sphincs_tester_192f,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Sign 10 C', sphincs_tester_128s,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Sign 10 C', sphincs_tester_128f,
	     args : [ 's', 'c' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE 256s Verify 1000 C', sphincs_tester_256s,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 256f Verify 1000 C', sphincs_tester_256f,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192s Verify 1000 C', sphincs_tester_192s,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 192f Verify 1000 C', sphincs_tester_192f,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128s Verify 1000 C', sphincs_tester_128s,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)
	test('Sphincs SHAKE 128f Verify 1000 C', sphincs_tester_128f,
	     args : [ 'v', 'c' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Sphincs SHAKE Official', sphincs_official_tester,
	     suite: regression)

	test('Sphincs SHAKE IUF', sphincs_official_tester,
	     suite: regression)
endif
