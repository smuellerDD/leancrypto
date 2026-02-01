certdir = meson.project_source_root() + '/asn1/tests/testcerts/'
include_asn1_internal = include_directories([ '../src' ])

if get_option('x509_parser').enabled()
	asn1_tester = executable('asn1_tester',
			 [ 'asn1_tester.c',
			   '../../apps/src/lc_x509_generator_file_helper.c',
			   '../../apps/src/lc_x509_generator_checker.c',
			   '../../apps/src/lc_x509_generator_print.c',
			   internal_src ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto,
			 link_with: leancrypto_static_lib
			 )

	gmtime_tester = executable('gmtime_tester',
			 [ 'gmtime_tester.c' ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto,
			 )
	test('X.509 gmtime', gmtime_tester, suite: regression)

	if (dilithium_enabled)
		test('X.509 ML-DSA87 Root CA', asn1_tester,
		args: [ '-x', '-f', certdir + 'ml-dsa87_cacert.der', '--check-ca',
			'--check-selfsigned', '--issuer-cn', 'leancrypto test CA',
			'--subject-cn', 'leancrypto test CA',
			'--valid-from', '1729527728', '--valid-to', '2044210606',
			'--skid', '0a0b0c0d0e0f',
			'--akid', '0a0b0c0d0e0f',
			'--check-time' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)

		test('X.509 ML-DSA65 Int 1 CA', asn1_tester,
		args: [ '-x', '-f', certdir + 'ml-dsa65_int1.der', '--check-ca',
			'--issuer-cn', 'leancrypto test CA',
			'--subject-cn', 'leancrypto test int1',
			'--valid-from', '1729527728', '--valid-to', '2044210606',
			'--skid', '0b0c0d0e0f0001', '--akid', '0a0b0c0d0e0f',
			'--check-time' ],
			suite: regression)

		test('X.509 ML-DSA44 Int 2 CA', asn1_tester,
		args: [ '-x', '-f', certdir + 'ml-dsa44_int2.der', '--check-ca',
			'--issuer-cn', 'leancrypto test int1',
			'--subject-cn', 'leancrypto test int2',
			'--valid-from', '1729527728', '--valid-to', '2044210606',
			'--skid', '0c0d0e0f000102', '--akid', '0b0c0d0e0f0001',
			'--check-time' ],
			suite: regression)

		test('X.509 ML-DSA87 Leaf', asn1_tester,
		args: [ '-x', '-f', certdir + 'ml-dsa87_leaf.der', '--check-noca',
			'--issuer-cn', 'leancrypto test int2',
			'--subject-cn', 'leancrypto test leaf',
			'--valid-from', '1729527728', '--valid-to', '2044210606',
			'--skid', '0d0e0f00010203', '--akid', '0c0d0e0f000102',
			'--check-time' ],
			suite: regression)
	endif

	if get_option('dilithium_ed25519').enabled()
		test('X.509 ML-DSA44-ED25519 Int 2 CA', asn1_tester,
		args: [ '-x', '-f', certdir + 'ml-dsa44-ed25519_int2.der', '--check-ca',
			'--issuer-cn', 'leancrypto test int1',
			'--subject-cn', 'leancrypto test int2',
			'--valid-from', '1729527728', '--valid-to', '2044210606',
			'--skid', '0c0d0e0f000102', '--akid', '0b0c0d0e0f0001',
			'--check-time' ],
			suite: regression)
	endif

	if (get_option('sphincs_shake_128s').enabled())
		test('X.509 SLH-DSA-SHAKE-128S Leaf', asn1_tester,
		args: [ '-x', '-f', certdir + 'slh-dsa-shake-128s_leaf.der', '--check-noca',
			'--issuer-cn', 'leancrypto test int2',
			'--subject-cn', 'leancrypto test leaf',
			'--valid-from', '1729527728', '--valid-to', '2044210606',
			'--skid', '0d0e0f00010203', '--akid', '0c0d0e0f000102',
			'--check-time' ],
			suite: regression)
	endif

	if get_option('pkcs7_debug').enabled()
		test('X.509 Root CA', asn1_tester,
		args: [ '-x', '-f', certdir + 'cacert.der', '--check-ca',
			'--check-selfsigned', '--issuer-cn', 'leancrypto test CA',
			'--subject-cn', 'leancrypto test CA',
			'--valid-from', '1728850606', '--valid-to', '2044210606',
			'--unsupported-sig',
			'--skid', '3f95183ace35cfee4178814b2f9d55bb0d6e9dfc',
			'--akid', '3f95183ace35cfee4178814b2f9d55bb0d6e9dfc',
			'--check-time' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('X.509 Intermediate 1 CA', asn1_tester,
		args: [ '-x', '-f', certdir + 'int-1-cert-rsa.der', '--check-ca',
			'--check-noselfsigned', '--issuer-cn', 'leancrypto test CA',
			'--subject-cn', 'leancrypto intermediate 1',
			'--valid-from', '1729526143', '--valid-to', '1761062143',
			'--unsupported-sig',
			'--skid', 'cdc07b83cd20a358c46bf0c30d60b721dcb8c5fd',
			'--akid', '3f95183ace35cfee4178814b2f9d55bb0d6e9dfc' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('X.509 Intermediate 2 CA', asn1_tester,
		args: [ '-x', '-f', certdir + 'int-2-cert-rsa.der', '--check-ca',
			'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 1',
			'--subject-cn', 'leancrypto intermediate 2',
			'--valid-from', '1729526144', '--valid-to', '1761062144',
			'--unsupported-sig',
			'--skid', '5904df832b2d318935924d439716e8b5cb0bdc02',
			'--akid', 'cdc07b83cd20a358c46bf0c30d60b721dcb8c5fd' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('X.509 Leaf Cert', asn1_tester,
		args: [ '-x', '-f', certdir + 'leaf-cert-rsa.der', '--check-noca',
			'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 2',
			'--subject-cn', 'leancrypto.leaf.san', '--valid-from', '1729527728',
			'--valid-to', '1761063728', '--unsupported-sig', '--eku', '16',
			'--san-dns', 'leancrypto.leaf.san',
			'--skid', '585e7bee1e3aa0268bf72897e12816fab730b0eb',
			'--akid', '31aad81c43a60ee696b2f97500318668ac6ffe00' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('X.509 Leaf Cert', asn1_tester,
		args: [ '-x', '-f', certdir + 'leaf-cert-rsa.der', '--check-noca',
			'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 2',
			'--subject-cn', 'leancrypto@leaf.san', '--valid-from', '1729527728',
			'--valid-to', '1761063728', '--unsupported-sig', '--eku', '16',
			'--san-email', 'leancrypto@leaf.san',
			'--skid', '585e7bee1e3aa0268bf72897e12816fab730b0eb',
			'--akid', '31aad81c43a60ee696b2f97500318668ac6ffe00' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
	endif
endif

if get_option('x509_generator').enabled()
	x509_gen_tester = executable('x509_gen_tester',
			 [ 'x509_gen_tester.c',
			   internal_src ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto
			 )

	# Issuer == Subject, no AKID
	test('X.509 self-signed', x509_gen_tester,
	     args: [ '--eku', '50', '--ca', '--keyusage', '64',
		     '--skid', '0102030405', '--valid-from', '1729527728',
		     '--valid-to', '1761063728', '--subject-cn', 'leancrypto',
		     '--issuer-cn', 'leancrypto',
		     '--serial', '0102030405060708', '--check-selfsigned' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	# Issuer != Subject, no AKID
	test('X.509 not self-signed', x509_gen_tester,
	     args: [ '--eku', '50', '--ca', '--keyusage', '64',
		     '--skid', '0102030405', '--valid-from', '1729527728',
		     '--valid-to', '1761063728', '--subject-cn', 'leancrypto',
		     '--issuer-cn', 'othercert',
		     '--serial', '0102030405060708', '--check-noselfsigned' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	asn1_enc_tester = executable('asn1_enc_tester',
			 [ 'asn1_enc_tester.c',
			   'x509_extensions_test_asn1.c',
			   internal_src ],
			 include_directories:
			 [ include_internal_dirs,
			   include_asn1_internal
			 ],
			 dependencies: leancrypto,
			 link_with: leancrypto_static_lib
			 )
	test('X.509 Generator 1', asn1_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'leancrypto',
		     '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	# This should fail because the parser mandates the serial number
	test('X.509 Generator 2', asn1_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'leancrypto',
		     '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer' ],
	     should_fail: true, suite: regression)

	# This should fail because the parser mandates the issuer
	test('X.509 Generator 3', asn1_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'leancrypto',
		     '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject',
		     '--serial', '0102030405060708' ],
	     should_fail: true, suite: regression)

	# This should fail because the parser mandates the subject
	test('X.509 Generator 4', asn1_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'leancrypto',
		     '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     should_fail: true, suite: regression)

	test('X.509 Generator 5', asn1_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'leancrypto',
		     '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 6', asn1_enc_tester,
	     args: [ '--ca', '--san-dns', 'leancrypto',
		     '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 7', asn1_enc_tester,
	     args: [ '--san-dns', 'leancrypto',
		     '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 8', asn1_enc_tester,
	     args: [ '--san-ip', '1.1.1.1', '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 9', asn1_enc_tester,
	     args: [ '--keyusage', '64',
		     '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 10', asn1_enc_tester,
	     args: [ '--skid', '0102030405', '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 11', asn1_enc_tester,
	     args: [ '--akid', '08090a0b',
		     '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 12', asn1_enc_tester,
	     args: [ '--valid-from', '1729527728', '--valid-to', '1761063728',
		     '--subject-cn', 'subject', '--issuer-cn', 'issuer',
		     '--serial', '0102030405060708' ],
	     suite: regression,
	     should_fail: fips140_negative_expect_fail)

	test('X.509 Generator 13', asn1_enc_tester,
		args: [ '--eku', '50', '--ca', '--san-dns', 'leancrypto',
			'--san-ip', '1.1.1.1', '--keyusage', '64',
			'--skid', '0102030405', '--akid', '08090a0b',
			'--valid-from', '1729527728', '--valid-to', '2524608000',
			'--subject-cn', 'subject', '--issuer-cn', 'issuer',
			'--serial', '0102030405060708' ],
		suite: regression,
		should_fail: fips140_negative_expect_fail)

	asn1_extensions_enc_tester = executable('asn1_extensions_enc_tester',
			 [ 'asn1_extensions_enc_tester.c',
			   'x509_extensions_test_asn1.c',
			   internal_src ],
			 include_directories:
			 [ include_internal_dirs,
			   include_asn1_internal
			 ],
			 dependencies: leancrypto,
			 link_with: leancrypto_static_lib
			 )

	# Iterate through all flags being set / unset
	test('X.509 Ext EKU 1', asn1_extensions_enc_tester,
	     args: [ '--eku', '24' ],
	     suite: regression)
	test('X.509 Ext EKU 2', asn1_extensions_enc_tester,
	     args: [ '--eku', '56' ],
	     suite: regression)
	test('X.509 Ext EKU 3', asn1_extensions_enc_tester,
	     args: [ '--eku', '120' ],
	     suite: regression)
	test('X.509 Ext EKU 4', asn1_extensions_enc_tester,
	     args: [ '--eku', '248' ],
	     suite: regression)
	test('X.509 Ext EKU 5', asn1_extensions_enc_tester,
	     args: [ '--eku', '504' ],
	     suite: regression)
	test('X.509 Ext EKU 6', asn1_extensions_enc_tester,
	     args: [ '--eku', '1016' ],
	     suite: regression)
	test('X.509 Ext EKU 7', asn1_extensions_enc_tester,
	     args: [ '--eku', '1008' ],
	     suite: regression)
	test('X.509 Ext EKU 8', asn1_extensions_enc_tester,
	     args: [ '--eku', '992' ],
	     suite: regression)
	test('X.509 Ext EKU 9', asn1_extensions_enc_tester,
	     args: [ '--eku', '960' ],
	     suite: regression)
	test('X.509 Ext EKU 10', asn1_extensions_enc_tester,
	     args: [ '--eku', '896' ],
	     suite: regression)
	test('X.509 Ext EKU 11', asn1_extensions_enc_tester,
	     args: [ '--eku', '768' ],
	     suite: regression)

	test('X.509 Ext EKU CA', asn1_extensions_enc_tester,
	     args: [ '--eku', '50', '--ca' ],
	     suite: regression)
	test('X.509 Ext EKU CA SANEmail', asn1_extensions_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-email', 'smueller@a.b' ],
	     suite: regression)
	test('X.509 Ext EKU CA SANDNS', asn1_extensions_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'smueller' ],
	     suite: regression)
	test('X.509 Ext EKU CA SAN[DNS|IP]', asn1_extensions_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'smueller',
		     '--san-ip', '1.1.1.1' ],
	     suite: regression)
	test('X.509 Ext EKU CA SAN[DNS|IP] KU', asn1_extensions_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'smueller',
		     '--san-ip', '1.1.1.1', '--keyusage', '96' ],
	     suite: regression)
	test('X.509 Ext EKU CA SAN[DNS|IP] KU SKID', asn1_extensions_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'smueller',
		     '--san-ip', '1.1.1.1', '--keyusage', '96',
		     '--skid', '0102030405' ],
	     suite: regression)
	test('X.509 Ext EKU CA SAN[DNS|IP] KU SKID AKID', asn1_extensions_enc_tester,
	     args: [ '--eku', '50', '--ca', '--san-dns', 'smueller',
		     '--san-ip', '1.1.1.1', '--keyusage', '96',
		     '--skid', '0102030405', '--akid', '08090a0b' ],
	     suite: regression)
	test('X.509 Ext EKU SAN[DNS|IP] KU SKID AKID', asn1_extensions_enc_tester,
	     args: [ '--eku', '96', '--san-dns', 'smueller',
		     '--san-ip', '1.1.1.1', '--keyusage', '96',
		     '--skid', '0102030405', '--akid', '08090a0b' ],
	     suite: regression)
	test('X.509 Ext SAN[DNS|IP] KU SKID AKID', asn1_extensions_enc_tester,
	     args: [ '--san-dns', 'smueller',
		     '--san-ip', '1.1.1.1', '--keyusage', '96',
		     '--skid', '0102030405', '--akid', '08090a0b' ],
	     suite: regression)
	test('X.509 Ext SANIP KU SKID AKID', asn1_extensions_enc_tester,
	     args: [ '--san-ip', '1.1.1.1', '--keyusage', '96',
		     '--skid', '0102030405', '--akid', '08090a0b' ],
	     suite: regression,)
	test('X.509 Ext KU SKID AKID', asn1_extensions_enc_tester,
	     args: [ '--keyusage', '96',
		     '--skid', '0102030405', '--akid', '08090a0b' ],
	     suite: regression,)
	test('X.509 Ext SKID AKID', asn1_extensions_enc_tester,
	     args: [ '--skid', '0102030405', '--akid', '08090a0b' ],
	     suite: regression)
	test('X.509 Ext AKID', asn1_extensions_enc_tester,
	     args: [ '--akid', '08090a0b' ],
	     suite: regression)

	asn1_eku_enc_tester = executable('asn1_eku_enc_tester',
			 [ 'asn1_eku_enc_tester.c',
			   'x509_extensions_test_asn1.c',
			   internal_src ],
			 include_directories:
			 [ include_internal_dirs,
			   include_asn1_internal
			 ],
			 dependencies: leancrypto,
			 link_with: leancrypto_static_lib
			 )
	test('X.509 EKU 8', asn1_eku_enc_tester, args: [ '--eku', '8' ],
	     suite: regression)
	test('X.509 EKU 16', asn1_eku_enc_tester, args: [ '--eku', '16' ],
	     suite: regression)
	test('X.509 EKU 32', asn1_eku_enc_tester, args: [ '--eku', '32' ],
	     suite: regression)
	test('X.509 EKU 64', asn1_eku_enc_tester, args: [ '--eku', '64' ],
	     suite: regression)
	test('X.509 EKU 128', asn1_eku_enc_tester, args: [ '--eku', '128' ],
	     suite: regression)
	test('X.509 EKU 256', asn1_eku_enc_tester, args: [ '--eku', '256' ],
	     suite: regression)
	test('X.509 EKU 512', asn1_eku_enc_tester, args: [ '--eku', '512' ],
	     suite: regression)

	x509_siggen_sigver_tester = executable('x509_siggen_sigver_tester',
			 [ 'x509_siggen_sigver_tester.c',
			   '../../apps/src/lc_x509_generator_file_helper.c',
			   internal_src ],
			 include_directories: [ include_dirs,
						include_internal_dirs ],
			 link_with: leancrypto_static_lib
			 )

	if (get_option('dilithium_87').enabled())
		test('X.509 ML-DSA87 Leaf Signature', x509_siggen_sigver_tester,
			args: [ '--sk-file', certdir + 'ml-dsa87_leaf.privkey',
				'--x509-cert', certdir + 'ml-dsa87_leaf.der' ],
				suite: regression,
				should_fail: fips140_negative_expect_fail)
	endif

	if (get_option('sphincs_shake_128f').enabled())
		test('X.509 SLH-DSA-SHAKE-128f Leaf Signature',
			x509_siggen_sigver_tester,
			args: [ '--sk-file', certdir + 'slh-dsa-shake-128f_leaf.privkey',
				'--x509-cert', certdir + 'slh-dsa-shake-128f_leaf.der' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
	endif

	if get_option('dilithium_ed25519').enabled()
		test('X.509 Composite-ML-DSA44 Signature',
			x509_siggen_sigver_tester,
			args: [ '--sk-file', certdir + 'ml-dsa44-ed25519_int2.privkey',
				'--x509-cert', certdir + 'ml-dsa44-ed25519_int2.der' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
	endif
	if get_option('dilithium_ed448').enabled()
		test('X.509 Composite-ML-DSA87 Signature',
			x509_siggen_sigver_tester,
			args: [ '--sk-file', certdir + 'ml-dsa87-ed448_cacert.privkey',
				'--x509-cert', certdir + 'ml-dsa87-ed448_cacert.der' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
	endif

	if get_option('dilithium_ed25519').enabled()
		composite_sig_domsep = executable('composite_sig_domsep',
			 [ 'composite_sig_domsep.c' ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto,
			 link_with: leancrypto_static_lib
			 )

		test('X.509 Composite Domain Separation',
			composite_sig_domsep, suite: regression,
			should_fail: fips140_negative_expect_fail)
	endif

	composite_sig_tester = executable('composite_sig_tester',
		[ 'composite_sig_tester.c' ],
		include_directories: [ include_dirs, include_internal_dirs ],
		link_with: leancrypto_static_lib
		)

	test('X.509 Composite Signature',
		composite_sig_tester, suite: regression,
		should_fail: fips140_negative_expect_fail)
endif

if get_option('pkcs7_parser').enabled()
	pkcs7_trust_tester = executable('pkcs7_trust_tester',
			 [ 'pkcs7_trust_tester.c',
			   '../../apps/src/lc_x509_generator_file_helper.c',
			   internal_src ],
			 include_directories: [ include_internal_dirs ],
			 dependencies: leancrypto,
			 link_with: leancrypto_static_lib
			 )

	if get_option('pkcs7_debug').enabled()
		test('PKCS7 Search Root CA', asn1_tester,
		args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-ca',
			'--check-selfsigned', '--issuer-cn', 'leancrypto test CA',
			'--subject-cn', 'leancrypto test CA',
			'--unsupported-sig' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)

		test('PKCS7 Search Intermediate 1 CA', asn1_tester,
		args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-ca',
			'--check-noselfsigned', '--issuer-cn', 'leancrypto test CA',
			'--subject-cn', 'leancrypto intermediate 1',
			'--unsupported-sig' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('PKCS7 Search Intermediate 2 CA', asn1_tester,
		args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-ca',
			'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 1',
			'--subject-cn', 'leancrypto intermediate 2',
			'--unsupported-sig' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('PKCS7 Search Leaf Cert', asn1_tester,
		args: [ '-p', '-f', certdir + 'cacert.der.p7b', '--check-noca',
			'--check-noselfsigned', '--issuer-cn', 'leancrypto intermediate 2',
			'--subject-cn', 'leancrypto.leaf.san',
			'--unsupported-sig', '--eku', '16' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)

		test('PKCS7 Full Validation - Unsupported Certs', asn1_tester,
			args: [ '-v', certdir + 'cacert.der',
				'-f', certdir + 'cacert.der.p7b' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
	endif

	if (dilithium_enabled)
		test('PKCS7 Trust Validation - 1 CA Cert', pkcs7_trust_tester,
			args: [ '-f', certdir + 'ml-dsa87_cacert.der' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('PKCS7 Trust Validation - 2 CA Certs', pkcs7_trust_tester,
			args: [ '-f', certdir + 'ml-dsa87_cacert.der',
				'-f', certdir + 'ml-dsa65_int1.der' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('PKCS7 Trust Validation - 2 CA Certs no root', pkcs7_trust_tester,
			args: [ '-f', certdir + 'ml-dsa65_int1.der',
				'-f', certdir + 'ml-dsa87_cacert.der', '-e', '250' ],
			suite: regression)
		test('PKCS7 Trust Validation - 2 CA Certs broken chain', pkcs7_trust_tester,
			args: [ '-f', certdir + 'ml-dsa87_cacert.der',
				'-f', certdir + 'ml-dsa44_int2.der',
				'-e', '250' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('PKCS7 Trust Validation - 2 CA Certs no chain', pkcs7_trust_tester,
			args: [ '-f', certdir + 'ml-dsa65_int1.der',
				'-e', '250' ],
			suite: regression)

		test('PKCS7 Trust Validation - PKCS#7 with trust chain', pkcs7_trust_tester,
			args: [ '-f', certdir + 'ml-dsa87_cacert.der',
				'-p', certdir + 'ml-dsa.p7b',
				'-v', certdir + 'ml-dsa87_cacert.der' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
		test('PKCS7 Trust Validation - PKCS#7 without trust chain', pkcs7_trust_tester,
			args: [ '-p', certdir + 'ml-dsa.p7b',
				'-v', certdir + 'ml-dsa87_cacert.der',
				'-e', '249' ],
			suite: regression,
			should_fail: fips140_negative_expect_fail)
	endif
endif

if get_option('pkcs7_generator').enabled()
	pkcs7_trust_malicious1_tester = executable('pkcs7_trust_malicious1_tester',
		[ 'pkcs7_trust_malicious1_tester.c', internal_src ],
		include_directories: [ include_internal_dirs ],
		dependencies: leancrypto,
		link_with: leancrypto_lib
		)
	test('PKCS7 Trust Validation - Malicious Cert chain',
		pkcs7_trust_malicious1_tester, suite: regression,
		should_fail: fips140_negative_expect_fail)
endif

