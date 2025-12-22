seeded_selftest_enable = 0

if get_option('chacha20_drng').enabled()
	seeded_selftest_enable = 1

	chacha20_drng_tester = executable('chacha20_drng_tester',
				   [ 'chacha20_drng_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	chacha20_drng_tester_large = executable('chacha20_drng_tester_large',
				   [ 'chacha20_drng_tester_large.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('DRNG ChaCha20', chacha20_drng_tester, suite: regression)
	test('DRNG ChaCha20 large', chacha20_drng_tester_large, timeout: 600,
	     is_parallel: false, suite: performance)
endif

if get_option('kmac_drng').enabled()
	seeded_selftest_enable = 1

	kmac_drng_tester = executable('kmac_drng_tester',
				   [ 'kmac_drng_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	kmac_drng_tester_large = executable('kmac_drng_tester_large',
				   [ 'kmac_drng_tester_large.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	kmac_drng_tester_large_c = executable('kmac_drng_tester_large_c',
				   [ 'kmac_drng_tester_large_c.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	kmac_drng_tester_output = executable('kmac_drng_tester_output',
				   [ 'kmac_drng_tester_output.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('DRNG KMAC', kmac_drng_tester, suite: regression)
	test('DRNG KMAC Accel large', kmac_drng_tester_large, timeout: 600,
	     is_parallel: false, suite: performance)
	test('DRNG KMAC C large', kmac_drng_tester_large_c, timeout: 600,
	     is_parallel: false, suite: performance)
endif

if get_option('cshake_drng').enabled()
	seeded_selftest_enable = 1

	cshake_drng_tester = executable('cshake_drng_tester',
				   [ 'cshake_drng_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	cshake_drng_tester_large = executable('cshake_drng_tester_large',
				   [ 'cshake_drng_tester_large.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	cshake_drng_tester_large_c = executable('cshake_drng_tester_large_c',
				   [ 'cshake_drng_tester_large_c.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	cshake_drng_tester_output = executable('cshake_drng_tester_output',
				   [ 'cshake_drng_tester_output.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('DRNG cSHAKE', cshake_drng_tester, suite: regression)
	test('DRNG cSHAKE Accel large', cshake_drng_tester_large, timeout: 600,
	     is_parallel: false, suite: performance)
	test('DRNG cSHAKE C large', cshake_drng_tester_large_c, timeout: 600,
	     is_parallel: false, suite: performance)
endif

if (get_option('xdrbg').enabled() and get_option('sha3').enabled())
	seeded_selftest_enable = 1

	xdrbg256_tester = executable('xdrbg256_tester',
				   [ 'xdrbg256_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg256_tester_large = executable('xdrbg256_tester_large',
				   [ 'xdrbg256_tester_large.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg256_tester_large_c = executable('xdrbg256_tester_large_c',
				   [ 'xdrbg256_tester_large_c.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg256_tester_output = executable('xdrbg256_tester_output',
				   [ 'xdrbg256_tester_output.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg512_tester = executable('xdrbg512_tester',
				   [ 'xdrbg512_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg512_tester_large = executable('xdrbg512_tester_large',
				   [ 'xdrbg512_tester_large.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg512_tester_large_c = executable('xdrbg512_tester_large_c',
				   [ 'xdrbg512_tester_large_c.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('DRNG XDRBG 256', xdrbg256_tester, suite: regression)
	test('DRNG XDRBG 256 Accel large', xdrbg256_tester_large, timeout: 600,
	     is_parallel: false, suite: performance)
	test('DRNG XDRBG 256 C large', xdrbg256_tester_large_c, timeout: 600,
	     is_parallel: false, suite: performance)
	test('DRNG XDRBG 512', xdrbg512_tester, suite: regression)
	test('DRNG XDRBG 512 Accel large', xdrbg512_tester_large, timeout: 600,
	     is_parallel: false, suite: performance)
	test('DRNG XDRBG 512 C large', xdrbg512_tester_large_c, timeout: 600,
	     is_parallel: false, suite: performance)
endif

if (get_option('xdrbg').enabled() and get_option('ascon').enabled())
	seeded_selftest_enable = 1

	xdrbg128_tester = executable('xdrbg128_tester',
				   [ 'xdrbg128_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
 				   )
	xdrbg128_tester_large = executable('xdrbg128_tester_large',
				   [ 'xdrbg128_tester_large.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg128_tester_large_c = executable('xdrbg128_tester_large_c',
				   [ 'xdrbg128_tester_large_c.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	xdrbg128_tester_output = executable('xdrbg128_tester_output',
				   [ 'xdrbg128_tester_output.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('DRNG XDRBG 128', xdrbg128_tester, suite: regression)
	test('DRNG XDRBG 128 Accel large', xdrbg128_tester_large, timeout: 600,
	     is_parallel: false, suite: performance)
	test('DRNG XDRBG 128 C large', xdrbg128_tester_large_c, timeout: 600,
	     is_parallel: false, suite: performance)
endif

if get_option('drbg_hash').enabled()
	seeded_selftest_enable = 1

	hash_sha2_drbg_tester = executable('hash_sha2_drbg_tester',
				[ 'hash_drbg_tester.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	hash_sha2_drbg_tester_large = executable('hash_sha2_drbg_tester_large',
				[ 'hash_drbg_tester_large.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('DRNG Hash SHA2-512', hash_sha2_drbg_tester, suite: regression)
	test('DRNG Hash SHA2-512 large', hash_sha2_drbg_tester_large,
	     timeout: 1500, is_parallel: false, suite: performance)

#	Disabled as SHA3 DRBG is disabled in main meson.build
# 	if get_option('sha3').enabled()
# 		hash_sha3_drbg_tester = executable('hash_sha3_drbg_tester',
# 				[ 'hash_sha3_drbg_tester.c', internal_src ],
# 				include_directories: [ include_internal_dirs ],
# 				dependencies: leancrypto
# 				)
# 		test('Hash SHA3-512', hash_sha3_drbg_tester)
# 	endif
endif

if get_option('drbg_hmac').enabled()
	seeded_selftest_enable = 1

	hmac_sha2_drbg_tester = executable('hmac_sha2_drbg_tester',
				[ 'hmac_drbg_tester.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	hmac_sha2_drbg_tester_large = executable('hmac_sha2_drbg_tester_large',
				[ 'hmac_drbg_tester_large.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('DRNG HMAC SHA2-512', hmac_sha2_drbg_tester, suite: regression)
	test('DRNG HMAC SHA2-512 large', hmac_sha2_drbg_tester_large,
	     timeout: 1500, is_parallel: false, suite: performance)
endif

if get_option('drbg_ctr').enabled()
	seeded_selftest_enable = 1

	ctr_drbg_tester = executable('ctr_drbg_tester',
				[ 'ctr_drbg_tester.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	ctr_drbg_tester_large = executable('ctr_drbg_tester_large',
				[ 'ctr_drbg_tester_large.c', internal_src ],
				include_directories: [ include_internal_dirs ],
				dependencies: leancrypto
				)
	test('DRNG CTR AES-256', ctr_drbg_tester, suite: regression)
	test('DRNG CTR DF AES-256 large', ctr_drbg_tester_large,
	     timeout: 1500, is_parallel: false, suite: performance)
	test('DRNG CTR NO DF AES-256 large', ctr_drbg_tester_large,
	     args : [ 'no' ], timeout: 1500, is_parallel: false, suite: performance)
endif

if (seeded_selftest_enable == 1)
	seeded_rng_tester = executable('seeded_rng_tester',
				   [ 'seeded_rng_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	test('DRNG Seeded RNG', seeded_rng_tester, suite: regression,
	     should_fail: fips140_negative_expect_fail)
endif
