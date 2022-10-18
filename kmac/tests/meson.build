kmac_128_tester = executable('kmac_128_tester',
			 [ 'kmac_128_tester.c', internal_src ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto
			 )
kmac_256_tester = executable('kmac_256_tester',
			 [ 'kmac_256_tester.c', internal_src ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto
			 )
kmac_xof_tester = executable('kmac_xof_tester',
			     [ 'kmac_xof_tester.c', internal_src ],
			     include_directories: [ include_internal_dirs ],
			     dependencies: leancrypto
			     )
kmac_xof_more_tester = executable('kmac_xof_more_tester',
			     [ 'kmac_xof_more_tester.c', internal_src ],
			     include_directories: [ include_internal_dirs ],
			     dependencies: leancrypto
			     )

test('KMAC 128', kmac_128_tester)
test('KMAC 256', kmac_256_tester)
test('KMAC XOF', kmac_xof_tester)
test('KMAC XOF iterative squeeze', kmac_xof_more_tester)
