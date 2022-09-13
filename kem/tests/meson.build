if get_option('kyber').enabled()
	include_kyber_internal = include_directories([ '../src' ])

	kyber_kex_tester = executable('kyber_kex_tester',
				[ 'kyber_kex_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: leancrypto_static_lib
				)
	kyber_ies_tester = executable('kyber_ies_tester',
				[ 'kyber_ies_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: leancrypto_static_lib
				)
	kyber_kem_tester = executable('kyber_kem_tester',
				[ 'kyber_kem_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				link_with: leancrypto_static_lib
				)

	test('Kyber KEX', kyber_kex_tester)
	test('Kyber IES', kyber_ies_tester)
	test('Kyber KEM', kyber_kem_tester)
endif
