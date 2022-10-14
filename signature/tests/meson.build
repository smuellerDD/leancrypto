if get_option('dilithium').enabled()
	include_dilithium_internal = include_directories([ '../src' ])

	dilithium_tester = executable('dilithium_tester',
				[ 'dilithium_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				link_with: leancrypto_static_lib
				)
	dilithium_invalid_tester = executable('dilithium_invalid_tester',
				[ 'dilithium_invalid_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs,
					include_dilithium_internal
				],
				link_with: leancrypto_static_lib
				)

	test('Dilithium signature', dilithium_tester, timeout: 300)
	test('Dilithium invalid signature', dilithium_invalid_tester)
endif
