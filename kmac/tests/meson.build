kmac_tester = executable('kmac_tester',
			 [ 'kmac_tester.c', internal_src ],
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

test('KMAC', kmac_tester)
test('KMAC XOF', kmac_xof_tester)
test('KMAC XOF iterative squeeze', kmac_xof_more_tester)
