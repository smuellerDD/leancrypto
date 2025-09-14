if get_option('dilithium_87').enabled()
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
				link_with: leancrypto_static_lib
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
	dilithium_keygen_tester = executable('dilithium_keygen_tester',
				[ 'dilithium_keygen_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
	dilithium_tester_official = executable('dilithium_tester_official',
				[ 'dilithium_tester_official.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
	dilithium_tester_ahat = executable('dilithium_tester_ahat',
				[ 'dilithium_tester_ahat.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)

	# Testing of ML-DSA keygen in FIPS mode (power up integrity test and
	# PCT)
	dilithium_keygen_fips_tester = executable('dilithium_keygen_fips_tester',
				[ 'dilithium_keygen_fips_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto_fips
				)

	test('Dilithium signature C', dilithium_tester_c, suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium init update final C', dilithium_tester_iuf_c,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium signature Common', dilithium_tester_common,
	     suite: regression)
	test('Dilithium init update final C', dilithium_tester_iuf_common,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium official API', dilithium_tester_official,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('Dilithium signature C 10000', dilithium_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Dilithium init update final C 10000', dilithium_tester_iuf_c,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Dilithium signature Common 10000', dilithium_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Dilithium invalid signature', dilithium_invalid_tester,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium keygen Performance', dilithium_keygen_tester,
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Dilithium C keep AHat API 10000', dilithium_tester_ahat,
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Dilithium C discard AHat API 10000', dilithium_tester_ahat,
	     args : [ 'd' ], timeout: 1000, is_parallel: false, suite: performance)

	test('Dilithium FIPS keygen', dilithium_keygen_fips_tester,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	if (x86_64_asm)
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

		test('Dilithium signature AVX2', dilithium_tester_avx2,
		     suite: regression,
	     should_fail: fips140_negative_expect_fail)
		test('Dilithium init update final AVX2',
		     dilithium_tester_iuf_avx2, suite: regression,
	     should_fail: fips140_negative_expect_fail)
		test('Dilithium signature AVX2 10000', dilithium_tester_avx2,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium init update final AVX2 10000',
		     dilithium_tester_iuf_avx2,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (arm64_asm)
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

		test('Dilithium signature ARMv8', dilithium_tester_armv8,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium init update final ARMv8',
		     dilithium_tester_iuf_armv8, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium signature ARMv8 10000', dilithium_tester_armv8,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium init update final ARMv8 10000',
		     dilithium_tester_iuf_armv8,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (arm32_neon_asm)
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

		test('Dilithium signature ARMv7', dilithium_tester_armv7,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium init update final ARMv7',
		     dilithium_tester_iuf_armv7, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium signature ARMv7 10000', dilithium_tester_armv7,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium init update final ARMv7 10000',
		     dilithium_tester_iuf_armv7,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (riscv64_asm)
		dilithium_tester_riscv64 = executable('dilithium_tester_riscv64',
				[ 'dilithium_tester_riscv64.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
		dilithium_tester_iuf_riscv64 = executable('dilithium_tester_iuf_riscv64',
				[ 'dilithium_tester_iuf_riscv64.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)

		test('Dilithium signature RISCV64', dilithium_tester_riscv64,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium init update final RISCV64',
		     dilithium_tester_iuf_riscv64, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium signature RISCV64 10000', dilithium_tester_riscv64,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium init update final RISCV64 10000',
		     dilithium_tester_iuf_riscv64,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)

		dilithium_tester_riscv64_rvv = executable('dilithium_tester_riscv64_rvv',
				[ 'dilithium_tester_riscv64_rvv.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)
		dilithium_tester_iuf_riscv64_rvv = executable('dilithium_tester_iuf_riscv64_rvv',
				[ 'dilithium_tester_iuf_riscv64_rvv.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto
				)

		test('Dilithium signature RISCV64 RVV', dilithium_tester_riscv64_rvv,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium init update final RISCV64 RVV',
		     dilithium_tester_iuf_riscv64_rvv, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium signature RISCV64 RVV 10000', dilithium_tester_riscv64_rvv,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium init update final RISCV64 RVV 10000',
		     dilithium_tester_iuf_riscv64_rvv,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if (get_option('sha2-256').enabled())
		dilithium_edge_case_tester_c = executable('dilithium_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE'
					)
		dilithium_edge_case_tester_common = executable('dilithium_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE'
					)

		test('Dilithium 87 Edge Cases C',
		     dilithium_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 87 Edge Cases Common',
		     dilithium_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_external_mu_edge_case_tester_c = executable('dilithium_external_mu_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE',
						   '-DLC_DILITHIUM_EXTMU_REJECTION_TEST' ]
					)
		dilithium_external_mu_edge_case_tester_common = executable('dilithium_external_mu_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE',
						   '-DLC_DILITHIUM_EXTMU_REJECTION_TEST' ]
					)

		test('Dilithium Ext MU 87 Edge Cases C',
		     dilithium_external_mu_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Ext MU 87 Edge Cases Common',
		     dilithium_external_mu_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_pure_edge_case_tester_c = executable('dilithium_pure_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE',
						   '-DLC_DILITHIUM_PURE_REJECTION_TEST' ]
					)
		dilithium_pure_edge_case_tester_common = executable('dilithium_pure_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE',
						   '-DLC_DILITHIUM_PURE_REJECTION_TEST' ]
					)

		test('Dilithium Pure 87 Edge Cases C',
		     dilithium_pure_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Pure 87 Edge Cases Common',
		     dilithium_pure_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_prehash_edge_case_tester_c = executable('dilithium_prehash_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE',
						   '-DLC_DILITHIUM_PREHASH_REJECTION_TEST' ]
					)
		dilithium_prehash_edge_case_tester_common = executable('dilithium_prehash_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE',
						   '-DLC_DILITHIUM_PREHASH_REJECTION_TEST' ]
					)

		test('Dilithium Prehash 87 Edge Cases C',
		     dilithium_prehash_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Prehash 87 Edge Cases Common',
		     dilithium_prehash_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif

	if get_option('dilithium_ed25519').enabled()
		dilithium_ed25519_tester = executable('dilithium_ed25519_tester',
					[ 'dilithium_ed25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib
					)
		dilithium_ed25519_iuf_tester = executable('dilithium_ed25519_iuf_tester',
					[ 'dilithium_ed25519_iuf_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib
					)
		dilithium_ed25519_tester_official = executable('dilithium_ed25519_tester_official',
					[ 'dilithium_ed25519_tester_official.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto
					)
		test('Dilithium-ED25519 Signature', dilithium_ed25519_tester,
		     suite: regression)
		test('Dilithium-ED25519 IUF Signature', dilithium_ed25519_iuf_tester,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium-ED25519 official API', dilithium_ed25519_tester_official,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium-ED25519 signature Common 10000',
		     dilithium_ed25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium-ED25519 IUF signature Common 10000',
		     dilithium_ed25519_iuf_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if get_option('dilithium_ed448').enabled()
		dilithium_ed448_tester = executable('dilithium_ed448_tester',
					[ 'dilithium_ed448_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib
					)
		dilithium_ed448_iuf_tester = executable('dilithium_ed448_iuf_tester',
					[ 'dilithium_ed448_iuf_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib
					)
		dilithium_ed448_tester_official = executable('dilithium_ed448_tester_official',
					[ 'dilithium_ed448_tester_official.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto
					)
		test('Dilithium-ED448 Signature', dilithium_ed448_tester,
		     suite: regression)
		test('Dilithium-ED448 IUF Signature', dilithium_ed448_iuf_tester,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium-ED448 official API', dilithium_ed448_tester_official,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium-ED448 signature Common 10000',
		     dilithium_ed448_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium-ED448 IUF signature Common 10000',
		     dilithium_ed448_iuf_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif
endif

if get_option('dilithium_65').enabled()
	include_dilithium_65_internal = include_directories([ '../src' ])

	dilithium_65_tester_c = executable('dilithium_65_tester_c',
				[ 'dilithium_tester_c.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
	dilithium_65_tester_iuf_c = executable('dilithium_65_tester_iuf_c',
				[ 'dilithium_tester_iuf_c.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
	dilithium_65_tester_iuf_common = executable('dilithium_65_tester_iuf_common',
				[ 'dilithium_tester_iuf_common.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
	dilithium_65_tester_common = executable('dilithium_65_tester_common',
				[ 'dilithium_tester_common.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs
				],
				link_with: leancrypto_static_lib,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
	dilithium_65_invalid_tester = executable('dilithium_65_invalid_tester',
				[ 'dilithium_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
	dilithium_65_keygen_tester = executable('dilithium_65_keygen_tester',
				[ 'dilithium_keygen_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
	dilithium_65_tester_official = executable('dilithium_65_tester_official',
				[ 'dilithium_tester_official.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
	dilithium_65_tester_ahat = executable('dilithium_65_tester_ahat',
				[ 'dilithium_tester_ahat.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)

	test('Dilithium 65 signature C', dilithium_65_tester_c,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 65 init update final C', dilithium_65_tester_iuf_c,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 65 signature Common', dilithium_65_tester_common,
	     suite: regression)
	test('Dilithium 65 init update final C', dilithium_65_tester_iuf_common,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 65 official API', dilithium_65_tester_official,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('Dilithium 65 signature C 10000', dilithium_65_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Dilithium 65 init update final C 10000', dilithium_65_tester_iuf_c,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Dilithium 65 signature Common 10000', dilithium_65_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Dilithium 65 invalid signature', dilithium_65_invalid_tester,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 65 keygen Performance', dilithium_65_keygen_tester,
	     timeout: 1000, is_parallel: false, suite: performance)

	test('Dilithium 65 C keep AHat API 10000', dilithium_65_tester_ahat,
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Dilithium 65 C discard AHat API 10000', dilithium_65_tester_ahat,
	     args : [ 'd' ], timeout: 1000, is_parallel: false, suite: performance)

	if (x86_64_asm)
		dilithium_65_tester_avx2 = executable('dilithium_65_tester_avx2',
				[ 'dilithium_tester_avx2.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
		dilithium_65_tester_iuf_avx2 = executable('dilithium_65_tester_iuf_avx2',
				[ 'dilithium_tester_iuf_avx2.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)

		test('Dilithium 65 signature AVX2', dilithium_65_tester_avx2,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 init update final AVX2',
		     dilithium_65_tester_iuf_avx2, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 signature AVX2 10000', dilithium_65_tester_avx2,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium 65 init update final AVX2 10000',
		     dilithium_65_tester_iuf_avx2,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (arm64_asm)
		dilithium_65_tester_armv8 = executable('dilithium_65_tester_armv8',
				[ 'dilithium_tester_armv8.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
		dilithium_65_tester_iuf_armv8 = executable('dilithium_65_tester_iuf_armv8',
				[ 'dilithium_tester_iuf_armv8.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)

		test('Dilithium 65 signature ARMv8', dilithium_65_tester_armv8,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 init update final ARMv8',
		     dilithium_65_tester_iuf_armv8, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 signature ARMv8 10000', dilithium_65_tester_armv8,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium 65 init update final ARMv8 10000',
		     dilithium_65_tester_iuf_armv8,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (arm32_neon_asm)
		dilithium_65_tester_armv7 = executable('dilithium_65_tester_armv7',
				[ 'dilithium_tester_armv7.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
		dilithium_65_tester_iuf_armv7 = executable('dilithium_65_tester_iuf_armv7',
				[ 'dilithium_tester_iuf_armv7.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)

		test('Dilithium 65 signature ARMv7', dilithium_65_tester_armv7,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 init update final ARMv7',
		     dilithium_65_tester_iuf_armv7, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 signature ARMv7 10000', dilithium_65_tester_armv7,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium 65 init update final ARMv7 10000',
		     dilithium_65_tester_iuf_armv7,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (riscv64_asm)
		dilithium_65_tester_riscv64 = executable('dilithium_65_tester_riscv64',
				[ 'dilithium_tester_riscv64.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
		dilithium_65_tester_iuf_riscv64 = executable('dilithium_65_tester_iuf_riscv64',
				[ 'dilithium_tester_iuf_riscv64.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)

		test('Dilithium 65 signature RISCV64', dilithium_65_tester_riscv64,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 init update final RISCV64',
		     dilithium_65_tester_iuf_riscv64, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 signature RISCV64 10000', dilithium_65_tester_riscv64,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium 65 init update final RISCV64 10000',
		     dilithium_65_tester_iuf_riscv64,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)

		dilithium_65_tester_riscv64_rvv = executable('dilithium_65_tester_riscv64_rvv',
				[ 'dilithium_tester_riscv64_rvv.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)
		dilithium_65_tester_iuf_riscv64_rvv = executable('dilithium_65_tester_iuf_riscv64_rvv',
				[ 'dilithium_tester_iuf_riscv64_rvv.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_65_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)

		test('Dilithium 65 signature RISCV64 RVV', dilithium_65_tester_riscv64_rvv,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 init update final RISCV64 RVV',
		     dilithium_65_tester_iuf_riscv64_rvv, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 signature RISCV64 RVV 10000', dilithium_65_tester_riscv64_rvv,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium 65 init update final RISCV64 RVV 10000',
		     dilithium_65_tester_iuf_riscv64_rvv,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if (get_option('sha2-256').enabled())
		dilithium_65_edge_case_tester_c = executable('dilithium_65_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)
		dilithium_65_edge_case_tester_common = executable('dilithium_65_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)

		test('Dilithium 65 Edge Cases C',
		     dilithium_65_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 65 Edge Cases Common',
		     dilithium_65_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_65_external_mu_edge_case_tester_c = executable('dilithium_65_external_mu_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_65',
						   '-DLC_DILITHIUM_EXTMU_REJECTION_TEST' ]
					)
		dilithium_65_external_mu_edge_case_tester_common = executable('dilithium_65_external_mu_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_65',
						   '-DLC_DILITHIUM_EXTMU_REJECTION_TEST' ]
					)

		test('Dilithium Ext MU 65 Edge Cases C',
		     dilithium_65_external_mu_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Ext MU 65 Edge Cases Common',
		     dilithium_65_external_mu_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_65_pure_edge_case_tester_c = executable('dilithium_65_pure_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_65',
						   '-DLC_DILITHIUM_PURE_REJECTION_TEST' ]
					)
		dilithium_65_pure_edge_case_tester_common = executable('dilithium_65_pure_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_65',
						   '-DLC_DILITHIUM_PURE_REJECTION_TEST' ]
					)

		test('Dilithium Pure 65 Edge Cases C',
		     dilithium_65_pure_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Pure 65 Edge Cases Common',
		     dilithium_65_pure_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_65_prehash_edge_case_tester_c = executable('dilithium_65_prehash_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_65',
						   '-DLC_DILITHIUM_PREHASH_REJECTION_TEST' ]
					)
		dilithium_65_prehash_edge_case_tester_common = executable('dilithium_65_prehash_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_65',
						   '-DLC_DILITHIUM_PREHASH_REJECTION_TEST' ]
					)

		test('Dilithium Prehash 65 Edge Cases C',
		     dilithium_65_prehash_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Prehash 65 Edge Cases Common',
		     dilithium_65_prehash_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif

	if get_option('dilithium_ed25519').enabled()
		dilithium_65_ed25519_tester = executable('dilithium_65_ed25519_tester',
					[ 'dilithium_ed25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)
		dilithium_65_ed25519_iuf_tester = executable('dilithium_65_ed25519_iuf_tester',
					[ 'dilithium_ed25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)
		dilithium_65_ed25519_tester_official = executable('dilithium_65_ed25519_tester_official',
					[ 'dilithium_ed25519_tester_official.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)
		test('Dilithium65-ED25519 Signature', dilithium_65_ed25519_tester,
		     suite: regression)
		test('Dilithium65-ED25519 IUF Signature', dilithium_65_ed25519_iuf_tester,
		     suite: regression)
		test('Dilithium65-ED25519 official API', dilithium_65_ed25519_tester_official,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium65-ED25519 signature Common 10000', dilithium_65_ed25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium65-ED25519 IUF signature Common 10000', dilithium_65_ed25519_iuf_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if get_option('dilithium_ed448').enabled()
		dilithium_65_ed448_tester = executable('dilithium_65_ed448_tester',
					[ 'dilithium_ed448_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)
		dilithium_65_ed448_iuf_tester = executable('dilithium_65_ed448_iuf_tester',
					[ 'dilithium_ed448_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)
		dilithium_65_ed448_tester_official = executable('dilithium_65_ed448_tester_official',
					[ 'dilithium_ed448_tester_official.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_65'
					)
		test('Dilithium65-ED448 Signature', dilithium_65_ed448_tester,
		     suite: regression)
		test('Dilithium65-ED448 IUF Signature', dilithium_65_ed448_iuf_tester,
		     suite: regression)
		test('Dilithium65-ED448 official API', dilithium_65_ed448_tester_official,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium65-ED448 signature Common 10000', dilithium_65_ed448_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium65-ED448 IUF signature Common 10000', dilithium_65_ed448_iuf_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif
endif

if get_option('dilithium_44').enabled()
	include_dilithium_44_internal = include_directories([ '../src' ])

	dilithium_44_tester_c = executable('dilithium_44_tester_c',
				[ 'dilithium_tester_c.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
	dilithium_44_tester_iuf_c = executable('dilithium_44_tester_iuf_c',
				[ 'dilithium_tester_iuf_c.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
	dilithium_44_tester_iuf_common = executable('dilithium_44_tester_iuf_common',
				[ 'dilithium_tester_iuf_common.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
	dilithium_44_tester_common = executable('dilithium_44_tester_common',
				[ 'dilithium_tester_common.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs
				],
				link_with: leancrypto_static_lib,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
	dilithium_44_invalid_tester = executable('dilithium_44_invalid_tester',
				[ 'dilithium_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
	dilithium_44_keygen_tester = executable('dilithium_44_keygen_tester',
				[ 'dilithium_keygen_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
	dilithium_44_tester_official = executable('dilithium_44_tester_official',
				[ 'dilithium_tester_official.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
	dilithium_44_tester_ahat = executable('dilithium_44_tester_ahat',
				[ 'dilithium_tester_ahat.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_65'
				)

	test('Dilithium 44 signature C', dilithium_44_tester_c,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 44 init update final C', dilithium_44_tester_iuf_c,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 44 signature Common', dilithium_44_tester_common,
	     suite: regression)
	test('Dilithium 44 init update final C', dilithium_44_tester_iuf_common,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 44 official API', dilithium_44_tester_official,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('Dilithium 44 signature C 10000', dilithium_44_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Dilithium 44 init update final C 10000', dilithium_44_tester_iuf_c,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Dilithium 44 signature Common 10000', dilithium_44_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Dilithium 44 invalid signature', dilithium_44_invalid_tester,
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)
	test('Dilithium 44 keygen Performance', dilithium_44_keygen_tester,
	     timeout: 1000, is_parallel: false, suite: performance)

	test('Dilithium 44 C keep AHat API 10000', dilithium_44_tester_ahat,
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Dilithium 44 C discard AHat API 10000', dilithium_44_tester_ahat,
	     args : [ 'd' ], timeout: 1000, is_parallel: false, suite: performance)

	if (get_option('sha2-256').enabled())
		dilithium_44_edge_case_tester_c = executable('dilithium_44_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)
		dilithium_44_edge_case_tester_common = executable('dilithium_44_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)

		test('Dilithium 44 Edge Cases C',
		     dilithium_44_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 44 Edge Cases Common',
		     dilithium_44_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_44_external_mu_edge_case_tester_c = executable('dilithium_44_external_mu_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_44',
						   '-DLC_DILITHIUM_EXTMU_REJECTION_TEST' ]
					)
		dilithium_44_external_mu_edge_case_tester_common = executable('dilithium_44_external_mu_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_44',
						   '-DLC_DILITHIUM_EXTMU_REJECTION_TEST' ]
					)

		test('Dilithium Ext MU 44 Edge Cases C',
		     dilithium_44_external_mu_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Ext MU 44 Edge Cases Common',
		     dilithium_44_external_mu_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_44_pure_edge_case_tester_c = executable('dilithium_44_pure_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_44',
						   '-DLC_DILITHIUM_PURE_REJECTION_TEST' ]
					)
		dilithium_44_pure_edge_case_tester_common = executable('dilithium_44_pure_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_44',
						   '-DLC_DILITHIUM_PURE_REJECTION_TEST' ]
					)

		test('Dilithium Pure 44 Edge Cases C',
		     dilithium_44_pure_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Pure 44 Edge Cases Common',
		     dilithium_44_pure_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		dilithium_44_prehash_edge_case_tester_c = executable('dilithium_44_prehash_edge_case_tester_c',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_c.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_44',
						   '-DLC_DILITHIUM_PREHASH_REJECTION_TEST' ]
					)
		dilithium_44_prehash_edge_case_tester_common = executable('dilithium_44_prehash_edge_case_tester_common',
					[ 'dilithium_edge_case_tester.c',
					'dilithium_edge_case_tester_common.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : [ '-DLC_DILITHIUM_TYPE_44',
						   '-DLC_DILITHIUM_PREHASH_REJECTION_TEST' ]
					)

		test('Dilithium Prehash 44 Edge Cases C',
		     dilithium_44_prehash_edge_case_tester_c, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium Prehash 44 Edge Cases Common',
		     dilithium_44_prehash_edge_case_tester_common, suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif

	if get_option('dilithium_ed25519').enabled()
		dilithium_44_ed25519_tester = executable('dilithium_44_ed25519_tester',
					[ 'dilithium_ed25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)
		dilithium_44_ed25519_iuf_tester = executable('dilithium_44_ed25519_iuf_tester',
					[ 'dilithium_ed25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)
		dilithium_44_ed25519_tester_official = executable('dilithium_44_ed25519_tester_official',
					[ 'dilithium_ed25519_tester_official.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)
		test('Dilithium44-ED25519 Signature', dilithium_44_ed25519_tester,
		     suite: regression)
		test('Dilithium44-ED25519 IUF Signature', dilithium_44_ed25519_iuf_tester,
		     suite: regression)
		test('Dilithium44-ED25519 official API', dilithium_44_ed25519_tester_official,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium44-ED25519 signature Common 10000', dilithium_44_ed25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium44-ED25519 IUF signature Common 10000', dilithium_44_ed25519_iuf_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if get_option('dilithium_ed448').enabled()
		dilithium_44_ed448_tester = executable('dilithium_44_ed448_tester',
					[ 'dilithium_ed448_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)
		dilithium_44_ed448_iuf_tester = executable('dilithium_44_ed448_iuf_tester',
					[ 'dilithium_ed448_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)
		dilithium_44_ed448_tester_official = executable('dilithium_44_ed448_tester_official',
					[ 'dilithium_ed448_tester_official.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_dilithium_internal
					],
					dependencies: leancrypto,
					c_args : '-DLC_DILITHIUM_TYPE_44'
					)
		test('Dilithium44-ED448 Signature', dilithium_44_ed448_tester,
		     suite: regression)
		test('Dilithium44-ED448 IUF Signature', dilithium_44_ed448_iuf_tester,
		     suite: regression)
		test('Dilithium44-ED448 official API', dilithium_44_ed448_tester_official,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium44-ED448 signature Common 10000', dilithium_44_ed448_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium44-ED448 IUF signature Common 10000', dilithium_44_ed448_iuf_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if (riscv64_asm)
		dilithium_44_tester_riscv64 = executable('dilithium_44_tester_riscv64',
				[ 'dilithium_tester_riscv64.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
		dilithium_44_tester_iuf_riscv64 = executable('dilithium_44_tester_iuf_riscv64',
				[ 'dilithium_tester_iuf_riscv64.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)

		test('Dilithium 44 signature RISCV64', dilithium_44_tester_riscv64,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 44 init update final RISCV64',
		     dilithium_44_tester_iuf_riscv64, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 44 signature RISCV64 10000', dilithium_44_tester_riscv64,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium 44 init update final RISCV64 10000',
		     dilithium_44_tester_iuf_riscv64,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)

		dilithium_44_tester_riscv64_rvv = executable('dilithium_44_tester_riscv64_rvv',
				[ 'dilithium_tester_riscv64_rvv.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)
		dilithium_44_tester_iuf_riscv64_rvv = executable('dilithium_44_tester_iuf_riscv64_rvv',
				[ 'dilithium_tester_iuf_riscv64_rvv.c',
				  'dilithium_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_44_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_DILITHIUM_TYPE_44'
				)

		test('Dilithium 44 signature RISCV64 RVV', dilithium_44_tester_riscv64_rvv,
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 44 init update final RISCV64 RVV',
		     dilithium_44_tester_iuf_riscv64_rvv, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Dilithium 44 signature RISCV64 RVV 10000', dilithium_44_tester_riscv64_rvv,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Dilithium 44 init update final RISCV64 RVV 10000',
		     dilithium_44_tester_iuf_riscv64_rvv,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif
endif
