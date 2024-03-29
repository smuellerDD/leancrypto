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
	dilithium_tester_iuf_c = executable('dilithium_tester_iuf_c',
				[ 'dilithium_tester_iuf_c.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
	dilithium_tester_iuf_common = executable('dilithium_tester_iuf_common',
				[ 'dilithium_tester_iuf_common.c',
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
	test('Dilithium init update final C', dilithium_tester_iuf_c)
	test('Dilithium signature Common', dilithium_tester_common)
	test('Dilithium init update final C', dilithium_tester_iuf_common)

	test('Dilithium signature C 10000', dilithium_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false)
	test('Dilithium init update final C 10000', dilithium_tester_iuf_c,
	     args : [ 'c' ], timeout: 1000, is_parallel: false)
	test('Dilithium signature Common 10000', dilithium_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false)
	test('Dilithium invalid signature', dilithium_invalid_tester)

	if (x86_64_asm and get_option('dilithium_strength') == '5')
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
		dilithium_tester_iuf_avx2 = executable('dilithium_tester_iuf_avx2',
				[ 'dilithium_tester_iuf_avx2.c',
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
		test('Dilithium init update final AVX2',
		     dilithium_tester_iuf_avx2)
		test('Dilithium signature AVX2 10000', dilithium_tester_avx2,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
		test('Dilithium init update final AVX2 10000',
		     dilithium_tester_iuf_avx2,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
	elif (arm64_asm and get_option('dilithium_strength') == '5')
		dilithium_tester_armv8 = executable('dilithium_tester_armv8',
				[ 'dilithium_tester_armv8.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
		dilithium_tester_iuf_armv8 = executable('dilithium_tester_iuf_armv8',
				[ 'dilithium_tester_iuf_armv8.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)

		test('Dilithium signature ARMv8', dilithium_tester_armv8)
		test('Dilithium init update final ARMv8',
		     dilithium_tester_iuf_armv8)
		test('Dilithium signature ARMv8 10000', dilithium_tester_armv8,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
		test('Dilithium init update final ARMv8 10000',
		     dilithium_tester_iuf_armv8,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
	elif (arm32_neon_gcc_asm and get_option('dilithium_strength') == '5')
		dilithium_tester_armv7 = executable('dilithium_tester_armv7',
				[ 'dilithium_tester_armv7.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
		dilithium_tester_iuf_armv7 = executable('dilithium_tester_iuf_armv7',
				[ 'dilithium_tester_iuf_armv7.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)

		test('Dilithium signature ARMv7', dilithium_tester_armv7)
		test('Dilithium init update final ARMv7',
		     dilithium_tester_iuf_armv7)
		test('Dilithium signature ARMv7 10000', dilithium_tester_armv7,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
		test('Dilithium init update final ARMv7 10000',
		     dilithium_tester_iuf_armv7,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
	endif

	if get_option('dilithium_ed25519').enabled()
		dilithium_ed25519_tester = executable('dilithium_ed25519_tester',
					[ 'dilithium_ed25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)
		test('Dilithium-ED25519 Signature', dilithium_ed25519_tester)
		test('Dilithium-ED25519 signature Common 10000', dilithium_ed25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
	endif
endif
