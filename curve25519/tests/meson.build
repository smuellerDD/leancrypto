if get_option('kyber_x25519').enabled() or get_option('dilithium_ed25519').enabled()

	x25519_tester = executable('x25519_tester',
				[ 'x25519_tester.c', internal_src ],
				include_directories: [
					include_dirs,
					include_internal_dirs
				], link_with: leancrypto_static_lib
				)
	test('ECDH X25519', x25519_tester)

	ed25519_tester = executable('ed25519_tester',
			[ 'ed25519_tester.c',
				internal_src ],
			include_directories: [
				include_dirs,
				include_internal_dirs
			],
			link_with: leancrypto_static_lib
			)
	test('EDDSA ED25519', ed25519_tester)

endif
