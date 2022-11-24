if get_option('dilithium').enabled()
	include_dilithium_internal = include_directories([ '../src' ])

	dilithium_tester_c = executable('dilithium_tester_c',
				[ 'dilithium_tester_c.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
	dilithium_tester_common = executable('dilithium_tester_common',
				[ 'dilithium_tester_common.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs
				],
				dependencies: leancrypto
				)
	dilithium_invalid_tester = executable('dilithium_invalid_tester',
				[ 'dilithium_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)

	test('Dilithium signature C', dilithium_tester_c)
	test('Dilithium signature Common', dilithium_tester_common)

	test('Dilithium signature C 10000', dilithium_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false)
	test('Dilithium signature Common 10000', dilithium_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false)
	test('Dilithium invalid signature', dilithium_invalid_tester)

	if (build_machine.cpu_family() == 'x86_64')
		dilithium_tester_avx2 = executable('dilithium_tester_avx2',
				[ 'dilithium_tester_avx2.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)

		test('Dilithium signature AVX2', dilithium_tester_avx2)
		test('Dilithium signature AVX2 10000', dilithium_tester_avx2,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
	endif
endif
