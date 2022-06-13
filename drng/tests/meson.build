if get_option('chacha20_drng').enabled()
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

	test('ChaCha20 DRNG', chacha20_drng_tester)
	test('ChaCha20 DRNG 1GB', chacha20_drng_tester_large, timeout: 300)
endif

if get_option('kmac_drng').enabled()
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
	kmac_drng_tester_output = executable('kmac_drng_tester_output',
				   [ 'kmac_drng_tester_output.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('KMAC DRNG', kmac_drng_tester)
	test('KMAC DRNG 1GB', kmac_drng_tester_large, timeout: 300)
endif

if get_option('cshake_drng').enabled()
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
	cshake_drng_tester_output = executable('cshake_drng_tester_output',
				   [ 'cshake_drng_tester_output.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('cSHAKE DRNG', cshake_drng_tester)
	test('cSHAKE DRNG 1GB', cshake_drng_tester_large, timeout: 300)
endif
