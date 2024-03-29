if get_option('kyber').enabled()
	include_kyber_internal = include_directories([ '../src' ])

	kyber_kex_tester = executable('kyber_kex_tester',
				[ 'kyber_kex_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)
	kyber_ies_tester = executable('kyber_ies_tester',
				[ 'kyber_ies_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)
	kyber_kem_tester_common = executable('kyber_kem_tester_common',
				[ 'kyber_kem_tester_common.c',
				  'kyber_kem_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)
	kyber_kem_kdf_tester_common = executable('kyber_kem_kdf_tester_common',
				[ 'kyber_kem_kdf_tester_common.c',
				  'kyber_kem_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)
	kyber_kem_tester_c = executable('kyber_kem_tester_c',
				[ 'kyber_kem_tester_c.c',
				  'kyber_kem_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)
	kyber_kem_kdf_tester_c = executable('kyber_kem_kdf_tester_c',
				[ 'kyber_kem_kdf_tester_c.c',
				  'kyber_kem_tester.c',
				  internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)
	kyber_invalid_tester = executable('kyber_invalid_tester',
				[ 'kyber_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)

	test('Kyber KEX', kyber_kex_tester)
	test('Kyber IES', kyber_ies_tester)
	test('Kyber KEM common', kyber_kem_tester_common)
	test('Kyber KEM C', kyber_kem_tester_c)
	test('Kyber KEM KDF common', kyber_kem_kdf_tester_common)
	test('Kyber KEM KDF C', kyber_kem_kdf_tester_c)
	test('Kyber KEM common 50000', kyber_kem_tester_common, args : [ 'c' ],
	     timeout: 1000, is_parallel: false)
	test('Kyber KEM C 50000', kyber_kem_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false)
	test('Kyber KEM KDF common 50000', kyber_kem_kdf_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false)
	test('Kyber KEM KDF C 50000', kyber_kem_kdf_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false)
	test('Kyber invalid KEM', kyber_invalid_tester)

	if (x86_64_asm and get_option('kyber_strength') == '4')
		kyber_kem_tester_avx2 = executable('kyber_kem_tester_avx2',
					[ 'kyber_kem_tester_avx2.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)
		kyber_kem_kdf_tester_avx2 = executable('kyber_kem_kdf_tester_avx2',
					[ 'kyber_kem_kdf_tester_avx2.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)

		test('Kyber KEM AVX2', kyber_kem_tester_avx2)
		test('Kyber KEM AVX2 50000', kyber_kem_tester_avx2,
		     args : [ 'avx2' ], timeout: 1000, is_parallel: false)
		test('Kyber KEM KDF AVX2', kyber_kem_kdf_tester_avx2)
		test('Kyber KEM KDF AVX2 50000', kyber_kem_kdf_tester_avx2,
		     args : [ 'avx2' ], timeout: 1000, is_parallel: false)
	elif (arm64_asm and get_option('kyber_strength') == '4')
		kyber_kem_tester_armv8 = executable('kyber_kem_tester_armv8',
					[ 'kyber_kem_tester_armv8.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)
		kyber_kem_kdf_tester_armv8 = executable('kyber_kem_kdf_tester_armv8',
					[ 'kyber_kem_kdf_tester_armv8.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)

		test('Kyber KEM ARMv8', kyber_kem_tester_armv8)
		test('Kyber KEM ARMv8 50000', kyber_kem_tester_armv8,
		     args : [ 'armv8' ], timeout: 1000, is_parallel: false)
		test('Kyber KEM KDF ARMv8', kyber_kem_kdf_tester_armv8)
		test('Kyber KEM KDF ARMv8 50000', kyber_kem_kdf_tester_armv8,
		     args : [ 'armv8' ], timeout: 1000, is_parallel: false)
	endif

	if get_option('kyber_x25519').enabled()
		kyber_ies_x25519_tester = executable('kyber_ies_x25519_tester',
					[ 'kyber_ies_x25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)
		kyber_kem_x25519_tester = executable('kyber_kem_x25519_tester',
					[ 'kyber_kem_x25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)
		kyber_kex_x25519_tester = executable('kyber_kex_x25519_tester',
					[ 'kyber_kex_x25519_tester.c',
					  internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)

		test('Kyber-X25519 IES', kyber_ies_x25519_tester)
		test('Kyber-X25519 KEM', kyber_kem_x25519_tester)
		test('Kyber-X25519 KEM 50000', kyber_kem_x25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false)
		test('Kyber-X25519 KEX', kyber_kex_x25519_tester)
	endif

endif
