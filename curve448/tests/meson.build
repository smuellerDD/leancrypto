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
	x448_keygen_tester = executable('x448_keygen_tester',
			[ 'x448_keygen_tester.c',
				internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			link_with: leancrypto_static_lib
			)
	x448_disabled_tester = executable('x448_disabled_tester',
			[ 'x448_disabled_tester.c',
				internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			link_with: leancrypto_lib
			)

	test('ECDH X448 Common', x448_tester, suite: regression)
	test('ECDH X448 C', x448_tester, suite: regression, args: [ 'c' ])
	test('ECDH X448 Common 100,000 scalar mult', x448_tester, suite: performance, args: [ 'p' ],
	     timeout: 2000, is_parallel: false)
	test('ECDH X448 C 100,000 scalar mult', x448_tester, suite: performance, args: [ 'p', 'c' ],
	     timeout: 2000, is_parallel: false)

	test('ECDH X448 Keygen Common', x448_keygen_tester, suite: regression)
	test('ECDH X448 Keygen C', x448_keygen_tester, suite: regression,
	     args: [ 'c' ])
	test('ECDH X448 Disabled', x448_disabled_tester, suite: regression)
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
	ed448_disabled_tester = executable('ed448_disabled_tester',
			[ 'ed448_disabled_tester.c',
				internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			link_with: leancrypto_lib
			)
	test('EDDSA ED448 Common', ed448_tester, suite: regression)
	test('EDDSA ED448 Disabled', ed448_disabled_tester,
	     suite: regression)
endif
