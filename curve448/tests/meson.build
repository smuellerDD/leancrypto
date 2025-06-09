if get_option('kyber_x448').enabled()
	x448_tester = executable('x448_tester',
			[ 'x448_tester.c',
				internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			link_with: leancrypto_static_lib
			)
	test('X448', x448_tester, suite: regression)
endif

if get_option('dilithium_ed448').enabled()
	ed448_tester = executable('ed448_tester',
			[ 'ed448_tester.c',
				internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			link_with: leancrypto_static_lib
			)
	test('EDDSA ED448', ed448_tester, suite: regression)
endif
