if get_option('chacha20').enabled()
	chacha20_block_tester = executable('chacha20_block_tester',
				   [ 'chacha20_block_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )
	chacha20_stream_tester = executable('chacha20_stream_tester',
				   [ 'chacha20_stream_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('Symmetric ChaCha20 block', chacha20_block_tester)
	test('Symmetric ChaCha20 stream', chacha20_stream_tester)
endif

if get_option('aes_block').enabled()
	aes_enc_tester = executable('aes_enc_tester',
					[ 'aes_enc_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)
	aes_dec_tester = executable('aes_dec_tester',
					[ 'aes_dec_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('Symmetric AES block encryption', aes_enc_tester)
	test('Symmetric AES block decryption', aes_dec_tester)
endif

if get_option('aes_ecb').enabled()
	aes_ecb_enc_tester = executable('aes_ecb_enc_tester',
					[ 'aes_ecb_enc_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)
	aes_ecb_dec_tester = executable('aes_ecb_dec_tester',
					[ 'aes_ecb_dec_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('Symmetric AES ECB encryption', aes_ecb_enc_tester)
	test('Symmetric AES ECB decryption', aes_ecb_dec_tester)
endif

if get_option('aes_cbc').enabled()
	aes_cbc_enc_tester = executable('aes_cbc_enc_tester',
					[ 'aes_cbc_enc_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)
	aes_cbc_dec_tester = executable('aes_cbc_dec_tester',
					[ 'aes_cbc_dec_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)
	aes_cbc_large_tester = executable('aes_cbc_large_tester',
					[ 'aes_cbc_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	# This is only present to compare its performance to the leancrypto impl
	# aes_cbc_openssl_large_tester = executable('aes_cbc_openssl_large_tester',
	#				[ 'aes_cbc_openssl_large_tester.c',
	#				internal_src ],
	#				include_directories: [ include_internal_dirs ],
	#				dependencies: [ leancrypto,
	#						dependency('openssl') ]
	#				)

	test('Symmetric AES CBC encryption', aes_cbc_enc_tester)
	test('Symmetric AES CBC decryption', aes_cbc_dec_tester)
	#test('AES CBC 1GB', aes_cbc_large_tester, timeout: 300)
	#test('AES CBC OpenSSL 1GB', aes_cbc_openssl_large_tester, timeout: 300)
endif

if get_option('aes_ctr').enabled()
	aes_ctr_tester = executable('aes_ctr_tester',
					[ 'aes_ctr_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	aes_ctr_large_tester = executable('aes_ctr_large_tester',
					[ 'aes_ctr_large_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('Symmetric AES CTR en/decryption', aes_ctr_tester)
	#test('AES CTR 1GB', aes_ctr_large_tester, timeout: 300)
endif

if get_option('aes_kw').enabled()
	aes_kw_tester = executable('aes_kw_tester',
					[ 'aes_kw_tester.c',
					internal_src ],
					include_directories: [ include_internal_dirs ],
					dependencies: leancrypto
					)

	test('Symmetric AES KW en/decryption', aes_kw_tester)
endif
