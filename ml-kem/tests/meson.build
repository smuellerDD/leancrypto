include_kyber_internal = include_directories([ '../src' ])

if get_option('kyber_1024').enabled()
	kyber_kex_tester = executable('kyber_kex_tester',
				[ 'kyber_kex_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib
				)
	if get_option('cshake_drng').enabled()
		kyber_ies_tester = executable('kyber_ies_tester',
					[ 'kyber_ies_tester.c', internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib
					)
	endif
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

	kyber_kem_official_tester = executable('kyber_kem_official_tester',
				[ 'kyber_kem_official_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], dependencies: leancrypto
				)
	kyber_keygen_tester = executable('kyber_keygen_tester',
				[ 'kyber_keygen_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], dependencies: leancrypto
				)

	# Testing of ML-KEM keygen in FIPS mode (power up integrity test and
	# PCT)
	kyber_keygen_fips_tester = executable('kyber_keygen_fips_tester',
				[ 'kyber_keygen_fips_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				dependencies: leancrypto_fips
				)
	kyber_modulus_tester = executable('kyber_modulus_tester',
				[ 'kyber_modulus_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				dependencies: leancrypto
				)

	test('Kyber KEX', kyber_kex_tester, suite: regression)
	if get_option('cshake_drng').enabled()
		test('Kyber IES', kyber_ies_tester, suite: regression)
	endif
	test('Kyber KEM common', kyber_kem_tester_common, suite: regression)
	test('Kyber KEM C', kyber_kem_tester_c, suite: regression)
	test('Kyber KEM KDF common', kyber_kem_kdf_tester_common,
	     suite: regression)
	test('Kyber KEM KDF C', kyber_kem_kdf_tester_c, suite: regression)
	test('Kyber KEM common 50000', kyber_kem_tester_common, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Kyber KEM C 50000', kyber_kem_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Kyber KEM KDF common 50000', kyber_kem_kdf_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber KEM KDF C 50000', kyber_kem_kdf_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Kyber invalid KEM', kyber_invalid_tester, suite: regression)
	test('Kyber official API KEM', kyber_kem_official_tester,
	     suite: regression)
	test('Kyber Keygen Performance', kyber_keygen_tester, timeout: 1000,
	     is_parallel: false, suite: performance)
	test('Kyber Keygen FIPS', kyber_keygen_fips_tester, suite: regression)
	test('Kyber Modulus Test Accel', kyber_modulus_tester,
	     suite: regression)
	test('Kyber Modulus Test C', kyber_modulus_tester,
	     args : [ 'c' ], suite: regression)

	if (x86_64_asm)
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

		test('Kyber KEM AVX2', kyber_kem_tester_avx2, suite: regression)
		test('Kyber KEM AVX2 50000', kyber_kem_tester_avx2,
		     args : [ 'avx2' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Kyber KEM KDF AVX2', kyber_kem_kdf_tester_avx2,
		     suite: regression)
		test('Kyber KEM KDF AVX2 50000', kyber_kem_kdf_tester_avx2,
		     args : [ 'avx2' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (arm64_asm)
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

		test('Kyber KEM ARMv8', kyber_kem_tester_armv8,
		     suite: regression)
		test('Kyber KEM ARMv8 50000', kyber_kem_tester_armv8,
		     args : [ 'armv8' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Kyber KEM KDF ARMv8', kyber_kem_kdf_tester_armv8,
		     suite: regression)
		test('Kyber KEM KDF ARMv8 50000', kyber_kem_kdf_tester_armv8,
		     args : [ 'armv8' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if get_option('kyber_x25519').enabled()
		if get_option('cshake_drng').enabled()
			kyber_ies_x25519_tester = executable('kyber_ies_x25519_tester',
						[ 'kyber_ies_x25519_tester.c',
						internal_src ],
						include_directories: [
							include_dirs,
							include_internal_dirs,
							include_kyber_internal
						], link_with: leancrypto_static_lib
						)
		endif
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

		if get_option('cshake_drng').enabled()
			test('Kyber-X25519 IES', kyber_ies_x25519_tester,
			     suite: regression)
		endif
		test('Kyber-X25519 KEM', kyber_kem_x25519_tester,
		     suite: regression)
		test('Kyber-X25519 KEM 50000', kyber_kem_x25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Kyber-X25519 KEX', kyber_kex_x25519_tester,
		     suite: regression)
	endif
endif

if get_option('kyber_768').enabled()
	kyber_768_kex_tester = executable('kyber_768_kex_tester',
				[ 'kyber_kex_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_768'
				)
	if get_option('cshake_drng').enabled()
		kyber_768_ies_tester = executable('kyber_768_ies_tester',
					[ 'kyber_ies_tester.c', internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_768'
					)
	endif
	kyber_768_kem_tester_common = executable('kyber_768_kem_tester_common',
				[ 'kyber_kem_tester_common.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_768'
				)
	kyber_768_kem_kdf_tester_common = executable('kyber_768_kem_kdf_tester_common',
				[ 'kyber_kem_kdf_tester_common.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_768'
				)
	kyber_768_kem_tester_c = executable('kyber_768_kem_tester_c',
				[ 'kyber_kem_tester_c.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_768'
				)
	kyber_768_kem_kdf_tester_c = executable('kyber_768_kem_kdf_tester_c',
				[ 'kyber_kem_kdf_tester_c.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_768'
				)
	kyber_768_invalid_tester = executable('kyber_768_invalid_tester',
				[ 'kyber_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_768'
				)
	kyber_768_kem_official_tester = executable('kyber_768_kem_official_tester',
				[ 'kyber_kem_official_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], dependencies: leancrypto,
				c_args : '-DLC_KYBER_TYPE_768'
				)
	kyber_768_keygen_tester = executable('kyber_768_keygen_tester',
				[ 'kyber_keygen_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], dependencies: leancrypto,
				c_args : '-DLC_KYBER_TYPE_768'
				)

	kyber_768_modulus_tester = executable('kyber_768_modulus_tester',
				[ 'kyber_modulus_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_KYBER_TYPE_768'
				)

	test('Kyber 768 KEX', kyber_768_kex_tester, suite: regression)
	if get_option('cshake_drng').enabled()
		test('Kyber 768 IES', kyber_768_ies_tester, suite: regression)
	endif
	test('Kyber 768 KEM common', kyber_768_kem_tester_common,
	     suite: regression)
	test('Kyber 768 KEM C', kyber_768_kem_tester_c, suite: regression)
	test('Kyber 768 KEM KDF common', kyber_768_kem_kdf_tester_common,
	     suite: regression)

	test('Kyber 768 KEM KDF C', kyber_768_kem_kdf_tester_c,
	     suite: regression)
	test('Kyber 768 KEM common 50000', kyber_768_kem_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber 768 KEM C 50000', kyber_768_kem_tester_c,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber 768 KEM KDF common 50000', kyber_768_kem_kdf_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber 768 KEM KDF C 50000', kyber_768_kem_kdf_tester_c,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber 768 invalid KEM', kyber_768_invalid_tester, suite: regression)
	test('Kyber 768 official API KEM', kyber_768_kem_official_tester,
	     suite: regression)
	test('Kyber 768 Keygen Performance', kyber_768_keygen_tester,
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Kyber 768 Modulus Test Accel', kyber_768_modulus_tester,
	     suite: regression)
	test('Kyber 768 Modulus Test C', kyber_768_modulus_tester,
	     args : [ 'c' ], suite: regression)

	if (x86_64_asm)
		kyber_768_kem_tester_avx2 = executable('kyber_768_kem_tester_avx2',
					[ 'kyber_kem_tester_avx2.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_768'
					)
		kyber_768_kem_kdf_tester_avx2 = executable('kyber_768_kem_kdf_tester_avx2',
					[ 'kyber_kem_kdf_tester_avx2.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_768'
					)

		test('Kyber 768 KEM AVX2', kyber_768_kem_tester_avx2,
		     suite: regression)
		test('Kyber 768 KEM AVX2 50000', kyber_768_kem_tester_avx2,
		     args : [ 'avx2' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Kyber 768 KEM KDF AVX2', kyber_768_kem_kdf_tester_avx2,
		     suite: regression)
		test('Kyber 768 KEM KDF AVX2 50000', kyber_768_kem_kdf_tester_avx2,
		     args : [ 'avx2' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	elif (arm64_asm)
		kyber_768_kem_tester_armv8 = executable('kyber_768_kem_tester_armv8',
					[ 'kyber_kem_tester_armv8.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_768'
					)
		kyber_768_kem_kdf_tester_armv8 = executable('kyber_768_kem_kdf_tester_armv8',
					[ 'kyber_kem_kdf_tester_armv8.c',
					'kyber_kem_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_768'
					)

		test('Kyber 768 KEM ARMv8', kyber_768_kem_tester_armv8,
		     suite: regression)
		test('Kyber 768 KEM ARMv8 50000', kyber_768_kem_tester_armv8,
		     args : [ 'armv8' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Kyber 768 KEM KDF ARMv8', kyber_768_kem_kdf_tester_armv8,
		     suite: regression)
		test('Kyber 768 KEM KDF ARMv8 50000', kyber_768_kem_kdf_tester_armv8,
		     args : [ 'armv8' ], timeout: 1000, is_parallel: false,
		     suite: performance)
	endif

	if get_option('kyber_x25519').enabled()
		if get_option('cshake_drng').enabled()
			kyber_768_ies_x25519_tester = executable('kyber_768_ies_x25519_tester',
						[ 'kyber_ies_x25519_tester.c',
						internal_src ],
						include_directories: [
							include_dirs,
							include_internal_dirs,
							include_kyber_internal
						], link_with: leancrypto_static_lib,
						c_args : '-DLC_KYBER_TYPE_768'
						)
		endif
		kyber_768_kem_x25519_tester = executable('kyber_768_kem_x25519_tester',
					[ 'kyber_kem_x25519_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_768'
					)
		kyber_768_kex_x25519_tester = executable('kyber_768_kex_x25519_tester',
					[ 'kyber_kex_x25519_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_768'
					)

		if get_option('cshake_drng').enabled()
			test('Kyber768-X25519 IES', kyber_768_ies_x25519_tester,
			     suite: regression)
		endif
		test('Kyber768-X25519 KEM', kyber_768_kem_x25519_tester,
		     suite: regression)
		test('Kyber768-X25519 KEM 50000', kyber_768_kem_x25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Kyber768-X25519 KEX', kyber_768_kex_x25519_tester,
		     suite: regression)
	endif
endif

if get_option('kyber_512').enabled()
	kyber_512_kex_tester = executable('kyber_512_kex_tester',
				[ 'kyber_kex_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	if get_option('cshake_drng').enabled()
		kyber_512_ies_tester = executable('kyber_512_ies_tester',
					[ 'kyber_ies_tester.c', internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_512'
					)
	endif
	kyber_512_kem_tester_common = executable('kyber_512_kem_tester_common',
				[ 'kyber_kem_tester_common.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	kyber_512_kem_kdf_tester_common = executable('kyber_512_kem_kdf_tester_common',
				[ 'kyber_kem_kdf_tester_common.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	kyber_512_kem_tester_c = executable('kyber_512_kem_tester_c',
				[ 'kyber_kem_tester_c.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	kyber_512_kem_kdf_tester_c = executable('kyber_512_kem_kdf_tester_c',
				[ 'kyber_kem_kdf_tester_c.c',
				'kyber_kem_tester.c',
				internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	kyber_512_invalid_tester = executable('kyber_512_invalid_tester',
				[ 'kyber_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], link_with: leancrypto_static_lib,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	kyber_512_kem_official_tester = executable('kyber_512_kem_official_tester',
				[ 'kyber_kem_official_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], dependencies: leancrypto,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	kyber_512_keygen_tester = executable('kyber_512_keygen_tester',
				[ 'kyber_keygen_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				], dependencies: leancrypto,
				c_args : '-DLC_KYBER_TYPE_512'
				)
	kyber_512_modulus_tester = executable('kyber_512_modulus_tester',
				[ 'kyber_modulus_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_kyber_internal
				],
				dependencies: leancrypto,
				c_args : '-DLC_KYBER_TYPE_512'
				)

	test('Kyber 512 KEX', kyber_512_kex_tester, suite: regression)
	if get_option('cshake_drng').enabled()
		test('Kyber 512 IES', kyber_512_ies_tester, suite: regression)
	endif
	test('Kyber 512 KEM common', kyber_512_kem_tester_common,
	     suite: regression)
	test('Kyber 512 KEM C', kyber_512_kem_tester_c, suite: regression)
	test('Kyber 512 KEM KDF common', kyber_512_kem_kdf_tester_common,
	     suite: regression)

	test('Kyber 512 KEM KDF C', kyber_512_kem_kdf_tester_c,
	     suite: regression)
	test('Kyber 512 KEM common 50000', kyber_512_kem_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber 512 KEM C 50000', kyber_512_kem_tester_c, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Kyber 512 KEM KDF common 50000', kyber_512_kem_kdf_tester_common,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber 512 KEM KDF C 50000', kyber_512_kem_kdf_tester_c,
	     args : [ 'c' ], timeout: 1000, is_parallel: false,
	     suite: performance)
	test('Kyber 512 invalid KEM', kyber_512_invalid_tester,
	     suite: regression)
	test('Kyber 512 official API KEM', kyber_512_kem_official_tester,
	     suite: regression)
	test('Kyber 512 Keygen Performance', kyber_512_keygen_tester,
	     timeout: 1000, is_parallel: false, suite: performance)
	test('Kyber 512 Modulus Test Accel', kyber_512_modulus_tester,
	     suite: regression)
	test('Kyber 512 Modulus Test C', kyber_512_modulus_tester,
	     args : [ 'c' ], suite: regression)

	if get_option('kyber_x25519').enabled()
		if get_option('cshake_drng').enabled()
			kyber_512_ies_x25519_tester = executable('kyber_512_ies_x25519_tester',
						[ 'kyber_ies_x25519_tester.c',
						internal_src ],
						include_directories: [
							include_dirs,
							include_internal_dirs,
							include_kyber_internal
						], link_with: leancrypto_static_lib,
						c_args : '-DLC_KYBER_TYPE_512'
						)
		endif
		kyber_512_kem_x25519_tester = executable('kyber_512_kem_x25519_tester',
					[ 'kyber_kem_x25519_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_512'
					)
		kyber_512_kex_x25519_tester = executable('kyber_512_kex_x25519_tester',
					[ 'kyber_kex_x25519_tester.c',
					internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs,
						include_kyber_internal
					], link_with: leancrypto_static_lib,
					c_args : '-DLC_KYBER_TYPE_512'
					)

		if get_option('cshake_drng').enabled()
			test('Kyber512-X25519 IES', kyber_512_ies_x25519_tester,
			     suite: regression)
		endif
		test('Kyber512-X25519 KEM', kyber_512_kem_x25519_tester,
		     suite: regression)
		test('Kyber512-X25519 KEM 50000', kyber_512_kem_x25519_tester,
		     args : [ 'c' ], timeout: 1000, is_parallel: false,
		     suite: performance)
		test('Kyber512-X25519 KEX', kyber_512_kex_x25519_tester,
		     suite: regression)
	endif
endif
