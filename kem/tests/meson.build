if get_option('kyber').enabled()
	include_kyber_internal = include_directories([ '../src' ])

	kyber_kex_tester = executable('kyber_kex_tester',
				[ 'kyber_kex_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: [ leancrypto_static_lib,
					     leancrypto_support_libs ]
				)
	kyber_ies_tester = executable('kyber_ies_tester',
				[ 'kyber_ies_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: [ leancrypto_static_lib, leancrypto_support_libs ]
				)
	kyber_kem_tester_common = executable('kyber_kem_tester_common',
				[ 'kyber_kem_tester_common.c',
				  'kyber_kem_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: [ leancrypto_static_lib,
					     leancrypto_support_libs ]
				)
	kyber_kem_tester_c = executable('kyber_kem_tester_c',
				[ 'kyber_kem_tester_c.c',
				  'kyber_kem_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: [ leancrypto_static_lib,
					     leancrypto_support_libs ]
				)
	kyber_invalid_tester = executable('kyber_invalid_tester',
				[ 'kyber_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: [ leancrypto_static_lib,
					     leancrypto_support_libs ]
				)

	test('Kyber KEX', kyber_kex_tester)
	test('Kyber IES', kyber_ies_tester)
	test('Kyber KEM common', kyber_kem_tester_common)
	test('Kyber KEM C', kyber_kem_tester_c)
	test('Kyber KEM common 50000', kyber_kem_tester_common, args : [ 'c' ],
	     timeout: 1000)
	test('Kyber KEM C 50000', kyber_kem_tester_c, args : [ 'c' ],
	     timeout: 1000)
	test('Kyber invalid KEM', kyber_invalid_tester)

	if (build_machine.cpu_family() == 'x86_64')
		kyber_kem_tester_avx2 = executable('kyber_kem_tester_avx2',
					[ 'kyber_kem_tester_avx2.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					],
					link_with: [ leancrypto_static_lib,
						leancrypto_support_libs ]
					)

		test('Kyber KEM AVX2', kyber_kem_tester_avx2)
		test('Kyber KEM AVX2 50000', kyber_kem_tester_avx2,
		     args : [ 'avx2' ], timeout: 1000)
	endif
endif
