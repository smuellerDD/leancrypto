if get_option('x509').enabled()
	asn1_tester = executable('asn1_tester',
			 [ 'asn1_tester.c', internal_src ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto,
			 link_with: leancrypto_static_lib
			 )

	certdir = meson.project_source_root() + '/asn1/tests/testcerts/'


	test('X.509 Root CA', asn1_tester,
	args: [ '-x', '-f', certdir + 'cacert.der', '--check-ca',
		'--check-selfsigned', '--issuer-cn', 'leancrypto test CA',
		'--subject-cn', 'leancrypto test CA',
		'--valid-from', '1728850606', '--valid-to', '2044210606',
		'--unsupported-sig',
		'--skid', '3f95183ace35cfee4178814b2f9d55bb0d6e9dfc',
		'--akid', '3f95183ace35cfee4178814b2f9d55bb0d6e9dfc',
		'--check-time' ],
		suite: regression)
	test('X.509 Intermediate 1 CA', asn1_tester,
	args: [ '-x', '-f', certdir + 'int-1-cert-rsa.der', '--check-ca',
		'--check-noselfsigned', '--issuer-cn', 'leancrypto test CA',
		'--subject-cn', 'leancrypto intermediate 1',
		'--valid-from', '1729526143', '--valid-to', '1761062143',
		'--unsupported-sig',
		'--skid', 'cdc07b83cd20a358c46bf0c30d60b721dcb8c5fd',
		'--akid', '3f95183ace35cfee4178814b2f9d55bb0d6e9dfc' ],
		suite: regression)
	test('X.509 Intermediate 2 CA', asn1_tester,
	args: [ '-x', '-f', certdir + 'int-2-cert-rsa.der', '--check-ca',
		'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 1',
		'--subject-cn', 'leancrypto intermediate 2',
		'--valid-from', '1729526144', '--valid-to', '1761062144',
		'--unsupported-sig',
		'--skid', '5904df832b2d318935924d439716e8b5cb0bdc02',
		'--akid', 'cdc07b83cd20a358c46bf0c30d60b721dcb8c5fd' ],
		suite: regression)
	test('X.509 Leaf Cert', asn1_tester,
	args: [ '-x', '-f', certdir + 'leaf-cert-rsa.der', '--check-noca',
		'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 2',
		'--subject-cn', 'leancrypto.leaf.san', '--valid-from', '1729527728',
		'--valid-to', '1761063728', '--unsupported-sig', '--eku', '16',
		'--san-dns', 'leancrypto.leaf.san',
		'--skid', '585e7bee1e3aa0268bf72897e12816fab730b0eb',
		'--akid', '31aad81c43a60ee696b2f97500318668ac6ffe00' ],
		suite: regression)
endif

if get_option('pkcs7').enabled()
	test('PKCS7 Search Root CA', asn1_tester,
	args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-ca',
		'--check-selfsigned', '--issuer-cn', 'leancrypto test CA',
		'--subject-cn', 'leancrypto test CA',
		'--unsupported-sig' ],
		suite: regression)

	test('PKCS7 Search Intermediate 1 CA', asn1_tester,
	args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-ca',
		'--check-noselfsigned', '--issuer-cn', 'leancrypto test CA',
		'--subject-cn', 'leancrypto intermediate 1',
		'--unsupported-sig' ],
		suite: regression)
	test('PKCS7 Search Intermediate 2 CA', asn1_tester,
	args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-ca',
		'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 1',
		'--subject-cn', 'leancrypto intermediate 2',
		'--unsupported-sig' ],
		suite: regression)
	test('PKCS7 Search Leaf Cert', asn1_tester,
	args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-noca',
		'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 2',
		'--subject-cn', 'leancrypto.leaf.san',
		'--unsupported-sig', '--eku', '16' ],
		suite: regression)


	if get_option('pkcs7_debug').enabled()
		test('PKCS7 Full Validation - Unsupported Certs', asn1_tester,
			args: [ '-v', certdir + 'cacert.der',
				'-f', certdir + 'cacert.der.p7b' ],
			suite: regression)
	endif
endif
