if get_option('kyber_x25519').enabled() or get_option('dilithium_ed25519').enabled()

	x25519_c_tester = executable('x25519_c_tester',
				[ 'x25519_c_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs
				], link_with: leancrypto_static_lib
				)
	test('ECDH X25519 C', x25519_c_tester, suite: regression)
	test('ECDH X25519 C Perf', x25519_c_tester, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)

	ed25519_tester = executable('ed25519_tester',
			[ 'ed25519_tester.c',
				internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			link_with: leancrypto_static_lib
			)
	test('EDDSA ED25519', ed25519_tester, suite: regression)

	x25519_common_tester = executable('x25519_common_tester',
				[ 'x25519_common_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs
				], link_with: leancrypto_static_lib
				)
	test('ECDH X25519 Common', x25519_common_tester, suite: regression)
	test('ECDH X25519 Common Perf', x25519_common_tester, args : [ 'c' ],
	     timeout: 1000, is_parallel: false, suite: performance)

	if (x86_64_asm)
		x25519_avx_tester = executable('x25519_avx_tester',
					[ 'x25519_avx_tester.c', internal_src ],
					include_directories: [
						include_dirs,
						include_internal_dirs
					], link_with: leancrypto_static_lib
					)
		test('ECDH X25519 AVX', x25519_avx_tester, suite: regression)
	endif

endif
