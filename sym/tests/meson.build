if get_option('chacha20').enabled()
	chacha20_block_tester = executable('chacha20_block_tester',
				   [ 'chacha20_block_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs,
							  '../src' ],
				   dependencies: leancrypto
				   )
	chacha20_stream_tester = executable('chacha20_stream_tester',
				   [ 'chacha20_stream_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs,
							  '../src' ],
				   dependencies: leancrypto
				   )
	chacha20_stream_large_tester = executable('chacha20_stream_large_tester',
				   [ 'chacha20_stream_large_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs,
							  '../src' ],
				   dependencies: leancrypto
				   )

	test('Symmetric ChaCha20 block', chacha20_block_tester,
	     suite: regression)
	test('Symmetric ChaCha20 stream Common', chacha20_stream_tester,
	     suite: regression)
	test('Symmetric ChaCha20 large Common', chacha20_stream_large_tester,
	     timeout: 600, is_parallel: false, suite: performance)
	test('Symmetric ChaCha20 large C', chacha20_stream_large_tester,
	     timeout: 600, is_parallel: false, suite: performance,
	     args: [ 'c' ])
endif

if get_option('aes_block').enabled()
	aes_enc_tester = executable('aes_enc_tester',
					[ 'aes_enc_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)
	aes_dec_tester = executable('aes_dec_tester',
					[ 'aes_dec_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)

	test('Symmetric AES block encryption', aes_enc_tester,
	     suite: regression)
	test('Symmetric AES block decryption', aes_dec_tester,
	     suite: regression)
endif

if get_option('aes_ecb').enabled()
	aes_ecb_enc_tester = executable('aes_ecb_enc_tester',
					[ 'aes_ecb_enc_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)
	aes_ecb_dec_tester = executable('aes_ecb_dec_tester',
					[ 'aes_ecb_dec_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)

	test('Symmetric AES ECB encryption', aes_ecb_enc_tester,
	     suite: regression)
	test('Symmetric AES ECB decryption', aes_ecb_dec_tester,
	     suite: regression)
endif

if get_option('aes_cbc').enabled()
	aes_cbc_enc_tester = executable('aes_cbc_enc_tester',
					[ 'aes_cbc_enc_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)
	aes_cbc_dec_tester = executable('aes_cbc_dec_tester',
					[ 'aes_cbc_dec_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)
	aes_cbc_large_tester = executable('aes_cbc_large_tester',
					[ 'aes_cbc_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)
	aes_cbc_c_large_tester = executable('aes_cbc_c_large_tester',
					[ 'aes_cbc_c_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)
	aes_cbc_aesni_large_tester = executable('aes_cbc_aesni_large_tester',
					[ 'aes_cbc_aesni_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)

	aes_cbc_armce_large_tester = executable('aes_cbc_armce_large_tester',
					[ 'aes_cbc_armce_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)
	aes_cbc_riscv64_large_tester = executable('aes_cbc_riscv64_large_tester',
					[ 'aes_cbc_riscv64_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)

#	This is only present to compare its performance to the leancrypto impl
# 	aes_cbc_openssl_large_tester = executable('aes_cbc_openssl_large_tester',
# 					[ 'aes_cbc_openssl_large_tester.c',
# 					internal_src ],
# 					include_directories: [ include_internal_dirs,
# 							  '../src' ],
# 					dependencies: [ leancrypto,
# 							dependency('openssl') ]
# 					)

	test('Symmetric AES CBC encryption', aes_cbc_enc_tester,
	     suite: regression)
	test('Symmetric AES CBC decryption', aes_cbc_dec_tester,
	     suite: regression)
	test('AES CBC C large', aes_cbc_c_large_tester, timeout: 2000,
	     is_parallel: false, suite: performance)
	test('AES CBC Accel large', aes_cbc_large_tester, timeout: 2000,
	     is_parallel: false, suite: performance)
#	test('AES CBC OpenSSL large', aes_cbc_openssl_large_tester, timeout: 300)
endif

if get_option('aes_ctr').enabled()
	aes_ctr_tester = executable('aes_ctr_tester',
					[ 'aes_ctr_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)

	aes_ctr_large_tester = executable('aes_ctr_large_tester',
					[ 'aes_ctr_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)

	test('Symmetric AES CTR en/decryption', aes_ctr_tester, suite: regression)
	#test('AES CTR large', aes_ctr_large_tester, timeout: 300)
endif

if get_option('aes_kw').enabled()
	aes_kw_tester = executable('aes_kw_tester',
					[ 'aes_kw_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs,
							  '../src' ],
					dependencies: leancrypto
					)

	test('Symmetric AES KW en/decryption', aes_kw_tester, suite: regression)
endif
