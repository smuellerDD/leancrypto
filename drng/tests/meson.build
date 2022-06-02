if get_option('chacha20_drng').enabled()
	chacha20_drng_tester = executable('chacha20_drng_tester',
				   [ 'chacha20_drng_tester.c',
				     internal_src ],
				   include_directories: [ include_internal_dirs ],
				   dependencies: leancrypto
				   )

	test('ChaCha20 DRNG', chacha20_drng_tester)
endif
