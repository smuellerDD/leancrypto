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

	test('ChaCha20 block', chacha20_block_tester)
	test('ChaCha20 stream', chacha20_stream_tester)
endif
