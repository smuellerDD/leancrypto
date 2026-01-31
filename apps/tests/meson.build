hasher_test_script = find_program('hasher-test.sh', required: true)
siggen_test_script = find_program('siggen_tester.sh', required: true)
sbsign_test_script = find_program('sbsign_test.sh', required: true)
sbvarsign_test_script = find_program('sbvarsign_test.sh', required: true)
sbsiglist_test_script = find_program('sbsiglist_test.sh', required: true)
sbattach_test_script = find_program('sbattach_test.sh', required: true)

# Application can be re-generated as outlined in README.md
# "Library Build for EFI Environment"
efi_test_file = meson.project_source_root() + '/apps/tests/pkcs7_trust_tester.efi'
rfc9882_test_script = find_program('rfc9882_test.sh', required: true)
certdir = meson.project_source_root() + '/asn1/tests/testcerts/'
rfc9882dir = meson.project_source_root() + '/apps/tests/'

x509_rootca_args = [
	'--keyusage', 'digitalSignature',
	'--keyusage', 'keyEncipherment',
	'--keyusage', 'keyCertSign',
	'--keyusage', 'critical',
	'--ca',
	'--valid-from', '1729527728',
	'--valid-to', '2044210606',
	'--subject-cn', 'leancrypto test CA',
	'--subject-ou', 'leancrypto test OU',
	'--subject-o', 'leancrypto',
	'--subject-st', 'Saxony',
	'--subject-c', 'DE',
	'--issuer-cn', 'leancrypto test CA',
	'--issuer-ou', 'leancrypto test OU',
	'--issuer-o', 'leancrypto',
	'--issuer-st', 'Saxony',
	'--issuer-c', 'DE',
	'--serial', '0102030405060708',
	'--skid', '0a0b0c0d0e0f',
	'--akid', '0a0b0c0d0e0f',
	'--noout',
	'--print',

	'--check-rootca',
	'--check-selfsigned',
	'--check-issuer-cn', 'leancrypto test CA',
	'--check-subject-cn', 'leancrypto test CA',
	'--check-valid-from', '1729527728',
	'--check-valid-to', '2044210606',
	'--check-skid', '0a0b0c0d0e0f',
	'--check-akid', '0a0b0c0d0e0f',
	'--check-time',
	'--check-keyusage', '16548'
	]

# This definition also checks that the validity is properly set by initializing
# the valid-from to be lower then the CA and and valid-to higher than the CA.
x509_int1_ca_args = [
	'--keyusage', 'digitalSignature',
	'--keyusage', 'keyEncipherment',
	'--keyusage', 'keyCertSign',
	'--keyusage', 'critical',
	'--ca',
	'--valid-from', '1729527727',
	'--valid-to', '2044210607',
	'--subject-cn', 'leancrypto test int1',
	'--subject-ou', 'leancrypto test OU',
	'--subject-o', 'leancrypto',
	'--subject-st', 'Saxony',
	'--subject-c', 'DE',
	'--serial', '0203030405060708',
	'--skid', '0b0c0d0e0f0001',
	'--noout',
	'--print',
	'--x509-signer', certdir + 'ml-dsa87_cacert.der',
	'--signer-sk-file', certdir + 'ml-dsa87_cacert.privkey',
	'--noout',
	'--print',

	'--check-ca',
	'--check-issuer-cn', 'leancrypto test CA',
	'--check-subject-cn', 'leancrypto test int1',
	'--check-valid-from', '1729527728',
	'--check-valid-to', '2044210606',
	'--check-skid', '0b0c0d0e0f0001',
	'--check-akid', '0a0b0c0d0e0f',
	'--check-time',
	'--check-keyusage', '16548'
	]

x509_leaf_args = [
	'--keyusage', 'dataEncipherment',
	'--keyusage', 'critical',
	'--eku', 'critical',
	'--eku', 'serverAuth',
	'--eku', 'codeSigning',
	'--valid-from', '1729527728',
	'--valid-to', '2044210606',
	'--subject-cn', 'leancrypto test leaf',
	'--subject-ou', 'leancrypto test OU',
	'--subject-o', 'leancrypto',
	'--subject-st', 'Saxony',
	'--subject-c', 'DE',
	'--serial', '0405060708090001',
	'--skid', '0d0e0f00010203',
	'--noout',
	'--print',
	'--x509-signer', certdir + 'ml-dsa44_int2.der',
	'--signer-sk-file', certdir + 'ml-dsa44_int2.privkey',
	'--noout',
	'--print',

	'--check-noca',
	'--check-issuer-cn', 'leancrypto test int2',
	'--check-subject-cn', 'leancrypto test leaf',
	'--check-valid-from', '1729527728',
	'--check-valid-to', '2044210606',
	'--check-skid', '0d0e0f00010203',
	'--check-akid', '0c0d0e0f000102',
	'--check-time',
	'--check-keyusage', '16400',
	'--check-eku', '82'
	]

pkcs7_arg_signer = [
	'--x509-signer', certdir + 'slh-dsa-shake-128f_leaf.der',
	'--signer-sk-file', certdir + 'slh-dsa-shake-128f_leaf.privkey',
	'-i', certdir + 'ml-dsa87_cacert.der',
	'--print',
	'--noout'
	]

pkcs7_arg_int1 = [
	'--x509-cert',  certdir + 'slh-dsa-shake-256f_int1.der'
	]

pkcs7_arg_int2 = [
	'--x509-cert', certdir + 'slh-dsa-shake-192f_int2.der'
	]

pkcs7_arg_ca = [
	'--x509-cert', certdir + 'slh-dsa-shake-256s_cacert.der'
	]

pkcs7_arg_trust = [
	'--trust-anchor', certdir + 'slh-dsa-shake-256s_cacert.der'
	]

pkcs7_arg_other_trust = [
	'--trust-anchor', certdir + 'ml-dsa87_cacert.der'
	]

# Trust Store tests
pkcs7_arg_trust_signer = [
	'--x509-signer', certdir + 'ml-dsa87_leaf.der',
	'--signer-sk-file', certdir + 'ml-dsa87_leaf.privkey',
	'-i', certdir + 'ml-dsa87_cacert.der',
	'--print',
	'--noout'
	]

pkcs7_arg_trust_ca = [
	'--trust-anchor', certdir + 'ml-dsa87_cacert.der'
	]

pkcs7_arg_trust_int1 = [
	'--trust-anchor', certdir + 'ml-dsa65_int1.der'
	]

pkcs7_arg_trust_int2 = [
	'--trust-anchor', certdir + 'ml-dsa44_int2.der'
	]

# Apps use POSIX API that is not available on regular Windows
if (host_machine.system() != 'windows' and
    get_option('efi').disabled() and
    get_option('apps').enabled())
	if get_option('sha2-256').enabled()
		test('sha256sum', hasher_test_script,
		     args: [ sha256sum.full_path(), '/usr/bin/sha256sum' ],
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif

	if get_option('sha2-512').enabled()
		test('sha512sum', hasher_test_script,
		     args: [ sha512sum.full_path(), '/usr/bin/sha512sum' ],
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif

	if get_option('sha3').enabled()
		test('sha3-256sum', hasher_test_script,
		     args: [ sha3_256sum.full_path(), '/usr/bin/sha3-256sum' ],
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('sha3-384sum', hasher_test_script,
		     args: [ sha3_384sum.full_path(), '/usr/bin/sha3-384sum' ],
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('sha3-512sum', hasher_test_script,
		     args: [ sha3_512sum.full_path(), '/usr/bin/sha3-512sum' ],
		     suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif

	if get_option('x509_generator').enabled()
		if (dilithium_enabled)
			test('X.509 Gen Root-CA ML-DSA87',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'ML-DSA87' ],
				timeout: 300, suite: regression,
				is_parallel: false,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA ML-DSA65',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'ML-DSA65' ],
				timeout: 300, suite: regression,
				is_parallel: false,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA ML-DSA44',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'ML-DSA44' ],
				timeout: 300, suite: regression,
				is_parallel: false,
				should_fail: fips140_negative_expect_fail)

			test('X.509 Gen Int-CA ML-DSA87',
				lc_x509_generator,
				args: [ x509_int1_ca_args, '--create-keypair',
					'ML-DSA87' ],
				timeout: 300, suite: regression,
				is_parallel: false,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Leaf ML-DSA87',
				lc_x509_generator,
				args: [ x509_leaf_args, '--create-keypair',
					'ML-DSA87' ],
				timeout: 300, suite: regression,
				is_parallel: false,
				should_fail: fips140_negative_expect_fail)
		endif

		if (sphincs_enabled)
			test('X.509 Gen Root-CA SLH-DSA-SHAKE-256S',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'SLH-DSA-SHAKE-256S' ],
				is_parallel: false, timeout: 600,
				suite: regression,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA SLH-DSA-SHAKE-256F',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'SLH-DSA-SHAKE-256F' ],
				is_parallel: false, timeout: 600,
				suite: regression,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA SLH-DSA-SHAKE-192S',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
				'SLH-DSA-SHAKE-192S' ],
				is_parallel: false, timeout: 600,
				suite: regression,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA SLH-DSA-SHAKE-192F',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
				'SLH-DSA-SHAKE-192F' ],
				is_parallel: false, timeout: 600,
				suite: regression,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA SLH-DSA-SHAKE-128S',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'SLH-DSA-SHAKE-128S' ],
				is_parallel: false, timeout: 600,
				suite: regression,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA SLH-DSA-SHAKE-128F',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'SLH-DSA-SHAKE-128F' ],
				is_parallel: false, timeout: 600,
				suite: regression,
				should_fail: fips140_negative_expect_fail)
		endif

		if get_option('dilithium_ed25519').enabled()
			test('X.509 Gen Root-CA ML-DSA65-ED25519',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'ML-DSA65-ED25519' ],
				timeout: 300, suite: regression,
				should_fail: fips140_negative_expect_fail)
			test('X.509 Gen Root-CA ML-DSA44-ED25519',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'ML-DSA44-ED25519' ],
				timeout: 300, suite: regression,
				should_fail: fips140_negative_expect_fail)
		endif

		if get_option('dilithium_ed448').enabled()
			test('X.509 Gen Root-CA ML-DSA87-ED448',
				lc_x509_generator,
				args: [ x509_rootca_args, '--create-keypair',
					'ML-DSA87-ED448' ],
				timeout: 300, suite: regression,
				should_fail: fips140_negative_expect_fail)
		endif

		x509_parser_test_script = find_program('leancrypto_check_with_ietf.sh',
						       required: true)
		test('X.509 Parsing other cryptoproviders',
		     x509_parser_test_script,
		     args: [ lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			     meson.project_source_root() + '/apps/tests/'
			   ],
		     timeout: 1000, suite: regression,
		     should_fail: fips140_negative_expect_fail)

	endif

	if get_option('pkcs7_generator').enabled()

		test('PKCS7 Gen with SLH-DSA 4-way cert chain',
			lc_pkcs7_generator,
			args: [ '--x509-signer', certdir + 'slh-dsa-shake-128f_leaf.der',
				'--signer-sk-file', certdir + 'slh-dsa-shake-128f_leaf.privkey',
				'-i', certdir + 'ml-dsa87_cacert.der',
				'--print',
				'--noout',
				'--x509-cert',  certdir + 'slh-dsa-shake-256f_int1.der',
				'--x509-cert', certdir + 'slh-dsa-shake-192f_int2.der',
				'--x509-cert', certdir + 'slh-dsa-shake-256s_cacert.der',
				'--trust-anchor', certdir + 'slh-dsa-shake-256s_cacert.der' ],
			is_parallel: false, timeout: 300, suite: regression,
			should_fail: fips140_negative_expect_fail)

		# SHA3-512 is default
		test('PKCS7 Gen with ML-DSA 4-way cert chain SHA3-512',
			lc_pkcs7_generator,
			args: [ '--x509-signer', certdir + 'ml-dsa87_leaf.der',
				'--signer-sk-file', certdir + 'ml-dsa87_leaf.privkey',
				'-i', certdir + 'ml-dsa87_cacert.der',
				'--print',
				'--noout',
				'--x509-cert',  certdir + 'ml-dsa65_int1.der',
				'--x509-cert', certdir + 'ml-dsa44_int2.der',
				'--x509-cert', certdir + 'ml-dsa87_cacert.der',
				'--trust-anchor', certdir + 'ml-dsa87_cacert.der' ],
			is_parallel: false, timeout: 300, suite: regression,
			should_fail: fips140_negative_expect_fail)

		if get_option('sha3').enabled()
			test('PKCS7 Gen with ML-DSA 4-way cert chain SHAKE256',
				lc_pkcs7_generator,
				args: [ '--md', 'SHAKE256',
					'--x509-signer', certdir + 'ml-dsa87_leaf.der',
					'--signer-sk-file', certdir + 'ml-dsa87_leaf.privkey',
					'-i', certdir + 'ml-dsa87_cacert.der',
					'--print',
					'--noout',
					'--x509-cert',  certdir + 'ml-dsa65_int1.der',
					'--x509-cert', certdir + 'ml-dsa44_int2.der',
					'--x509-cert', certdir + 'ml-dsa87_cacert.der',
					'--trust-anchor', certdir + 'ml-dsa87_cacert.der' ],
				is_parallel: false, timeout: 300,
				suite: regression,
				should_fail: fips140_negative_expect_fail)

			#This should fail as the requested message digest is
			#too weak for the signer
			test('PKCS7 Gen with ML-DSA 4-way cert chain SHA3-256',
				lc_pkcs7_generator,
				args: [ '--md', 'SHA3-256',
					'--x509-signer', certdir + 'ml-dsa87_leaf.der',
					'--signer-sk-file', certdir + 'ml-dsa87_leaf.privkey',
					'-i', certdir + 'ml-dsa87_cacert.der',
					'--print',
					'--noout',
					'--x509-cert',  certdir + 'ml-dsa65_int1.der',
					'--x509-cert', certdir + 'ml-dsa44_int2.der',
					'--x509-cert', certdir + 'ml-dsa87_cacert.der',
					'--trust-anchor', certdir + 'ml-dsa87_cacert.der' ],
				is_parallel: false, timeout: 300,
				should_fail: true, suite: regression)
		endif

		if get_option('sha2-512').enabled()
			test('PKCS7 Gen with ML-DSA 4-way cert chain SHA2-512',
			lc_pkcs7_generator,
				args: [ '--md', 'SHA2-512',
					'--x509-signer', certdir + 'ml-dsa87_leaf.der',
					'--signer-sk-file', certdir + 'ml-dsa87_leaf.privkey',
					'-i', certdir + 'ml-dsa87_cacert.der',
					'--print',
					'--noout',
					'--x509-cert',  certdir + 'ml-dsa65_int1.der',
					'--x509-cert', certdir + 'ml-dsa44_int2.der',
					'--x509-cert', certdir + 'ml-dsa87_cacert.der',
					'--trust-anchor', certdir + 'ml-dsa87_cacert.der' ],
				is_parallel: false, timeout: 300,
				suite: regression,
				should_fail: fips140_negative_expect_fail)
		endif

		# Generate the PKCS#7 message, verify it and check the key usage
		# and EKU of the signer
		if get_option('dilithium_ed25519').enabled()
			test('PKCS7 Gen with ML-DSA-ED25519 4-way cert chain',
			     lc_pkcs7_generator,
			     args: [ '--x509-signer', certdir + 'slh-dsa-shake-128s_leaf.der',
				'--signer-sk-file', certdir + 'slh-dsa-shake-128s_leaf.privkey',
				'-i', certdir + 'ml-dsa87_cacert.der',
				'--print',
				'--noout',
				'--x509-cert',  certdir + 'ml-dsa65-ed25519_int1.der',
				'--x509-cert', certdir + 'ml-dsa44-ed25519_int2.der',
				'--x509-cert', certdir + 'ml-dsa87-ed448_cacert.der',
				'--trust-anchor', certdir + 'ml-dsa87-ed448_cacert.der',
				'--expected-eku', 'ServerAuthentication',
				'--expected-eku', 'CodeSigning',
				'--expected-keyusage', 'dataEncipherment'
				],
			is_parallel: false, timeout: 300, suite: regression,
			should_fail: fips140_negative_expect_fail)

			# Generate the PKCS#7 message, verify it and check the key usage
			# and EKU of the signer where the EKU will be not matched
			test('PKCS7 Gen with ML-DSA-ED25519 4-way cert chain',
			     lc_pkcs7_generator,
			     args: [ '--x509-signer', certdir + 'slh-dsa-shake-128s_leaf.der',
				'--signer-sk-file', certdir + 'slh-dsa-shake-128s_leaf.privkey',
				'-i', certdir + 'ml-dsa87_cacert.der',
				'--print',
				'--noout',
				'--x509-cert',  certdir + 'ml-dsa65-ed25519_int1.der',
				'--x509-cert', certdir + 'ml-dsa44-ed25519_int2.der',
				'--x509-cert', certdir + 'ml-dsa87-ed448_cacert.der',
				'--trust-anchor', certdir + 'ml-dsa87-ed448_cacert.der',
				'--expected-eku', 'ServerAuthentication',
				'--expected-eku', 'ClientAuthentication',
				'--expected-eku', 'CodeSigning',
				'--expected-keyusage', 'dataEncipherment'
				],
			is_parallel: false, should_fail: true, timeout: 300, suite: regression)
		endif

		# Trust-Store enabled with cert chain leading to CA that is in
		# trust store
		test('PKCS7 Gen with valid Trust-Store',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2,
			     pkcs7_arg_ca,
			     pkcs7_arg_trust ],
		     is_parallel: false, timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		# Trust-Store enabled with cert chain leading to CA
		# Although certificate chain has no root CA, it is taken from
		# Trust Store
		test('PKCS7 Gen with valid Trust-Store 2',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2,
			     pkcs7_arg_trust ],
		     is_parallel: false, timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		# Trust-Store enabled with cert chain not leading to the CA
		# signing the intermediate 1
		# -> failure in certificate chain validation
		test('PKCS7 Gen with broken chain to Trust-Store',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2,
			     pkcs7_arg_ca,
			     pkcs7_arg_other_trust ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)

		# Trust-Store disabled but with root CA cert
		test('PKCS7 Gen no Trust-Store',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2,
			     pkcs7_arg_ca, ],
		     is_parallel: false, timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		# Trust-Store disabled but without root CA cert
		# -> failure in certificate chain validation
		test('PKCS7 Gen no root CA',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2 ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)

		# Missing intermediate 1 in PKCS#7
		test('PKCS7 Gen with missing intermediate',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int2,
			     pkcs7_arg_ca,
			     pkcs7_arg_other_trust ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)

		# CA, intermediate 1, intermediate 2 in trust store
		test('PKCS7 Gen Trust Store 1',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_trust_signer,
			     pkcs7_arg_trust_ca,
			     pkcs7_arg_trust_int1,
			     pkcs7_arg_trust_int2
			   ],
		     is_parallel: false, timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		# CA, intermediate 1, in trust store -> intermediate 2 missing
		# -> fails during certificate chain validation
		test('PKCS7 Gen Trust Store 2',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_trust_signer,
			     pkcs7_arg_trust_ca,
			     pkcs7_arg_trust_int1
			   ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)

		# CA, intermediate 2, in trust store -> intermediate 1 missing
		# -> fails during loading of certificate 2
		test('PKCS7 Gen Trust Store 3',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_trust_signer,
			     pkcs7_arg_trust_ca,
			     pkcs7_arg_trust_int2
			   ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)

		# CA, intermediate 1 and intermediate 2 in trust store, but
		# loaded CA is not the CA signing intermediate 1
		# -> fails during loading of certificate 1
		test('PKCS7 Gen Trust Store 4',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_trust_signer,
			     pkcs7_arg_ca,
			     pkcs7_arg_trust_int1,
			     pkcs7_arg_trust_int2
			   ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)

		test('PKCS7 Check message',
			lc_pkcs7_generator,
			args: [ '--print-pkcs7',  certdir + 'ml-dsa.p7b',
				'--check-rootca',
				'--check-ca',
				'--check-selfsigned',
				'--check-issuer-cn', 'leancrypto test CA',
				'--check-subject-cn', 'leancrypto test int1',
				'--check-keyusage', '16548'

			],
			is_parallel: false, timeout: 300, suite: regression,
			should_fail: fips140_negative_expect_fail)

		# These tests do not fail in FIPS mode, because they do not
		# perform cryptographic operations
		test('RFC9882 ML-DSA87 Test Vector',
		     rfc9882_test_script,
		     args: [ rfc9882dir + 'rfc9882_cms_mldsa87.pem',
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression)
		test('RFC9882 ML-DSA65 Test Vector',
		     rfc9882_test_script,
		     args: [ rfc9882dir + 'rfc9882_cms_mldsa65.pem',
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression)
		test('RFC9882 ML-DSA44 Test Vector',
		     rfc9882_test_script,
		     args: [ rfc9882dir + 'rfc9882_cms_mldsa44.pem',
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression)

	endif

	if get_option('pkcs8_generator').enabled()
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop ML-DSA87',
		     siggen_test_script,
		     args: [ 'ML-DSA87',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop ML-DSA65',
		     siggen_test_script,
		     args: [ 'ML-DSA65',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop ML-DSA44',
		     siggen_test_script,
		     args: [ 'ML-DSA44',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('X.509/PKCS8 keygen/siggen/sigver ML-DSA87-ED448',
		     siggen_test_script,
		     args: [ 'ML-DSA87-ED448',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver ML-DSA65-ED25519',
		     siggen_test_script,
		     args: [ 'ML-DSA65-ED25519',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver ML-DSA44-ED25519',
		     siggen_test_script,
		     args: [ 'ML-DSA44-ED25519',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop SLH-DSA-SHAKE-128F',
		     siggen_test_script,
		     args: [ 'SLH-DSA-SHAKE-128F',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop SLH-DSA-SHAKE-128S',
		     siggen_test_script,
		     args: [ 'SLH-DSA-SHAKE-128S',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop SLH-DSA-SHAKE-192F',
		     siggen_test_script,
		     args: [ 'SLH-DSA-SHAKE-192F',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop SLH-DSA-SHAKE-192S',
		     siggen_test_script,
		     args: [ 'SLH-DSA-SHAKE-192S',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop SLH-DSA-SHAKE-256F',
		     siggen_test_script,
		     args: [ 'SLH-DSA-SHAKE-256F',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('X.509/PKCS8 keygen/siggen/sigver LC - OpenSSL Interop SLH-DSA-SHAKE-256S',
		     siggen_test_script,
		     args: [ 'SLH-DSA-SHAKE-256S',
			     lc_x509_generator.full_path(),
			     lc_pkcs7_generator.full_path(),
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif

	if get_option('sbsigntools').enabled()
		test('Secure boot sbsign tool ML-DSA87',
		     sbsign_test_script,
		     args: [ 'ML-DSA87',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool ML-DSA65',
		     sbsign_test_script,
		     args: [ 'ML-DSA65',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool ML-DSA44',
		     sbsign_test_script,
		     args: [ 'ML-DSA44',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('Secure boot sbsign tool ML-DSA87-ED448',
		     sbsign_test_script,
		     args: [ 'ML-DSA87-ED448',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool ML-DSA65-ED25519',
		     sbsign_test_script,
		     args: [ 'ML-DSA65-ED25519',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool ML-DSA44-ED25519',
		     sbsign_test_script,
		     args: [ 'ML-DSA44-ED25519',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('Secure boot sbsign tool SLH-DSA-SHAKE-128F',
		     sbsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-128F',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool SLH-DSA-SHAKE-128S',
		     sbsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-128S',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool SLH-DSA-SHAKE-192F',
		     sbsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-192F',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool SLH-DSA-SHAKE-192S',
		     sbsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-192S',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool SLH-DSA-SHAKE-256F',
		     sbsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-256F',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbsign tool SLH-DSA-SHAKE-256S',
		     sbsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-256S',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbverify.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('Secure boot sbvarsign tool ML-DSA87',
		     sbvarsign_test_script,
		     args: [ 'ML-DSA87',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool ML-DSA65',
		     sbvarsign_test_script,
		     args: [ 'ML-DSA65',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool ML-DSA44',
		     sbvarsign_test_script,
		     args: [ 'ML-DSA44',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('Secure boot sbvarsign tool ML-DSA87-ED448',
		     sbvarsign_test_script,
		     args: [ 'ML-DSA87-ED448',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool ML-DSA65-ED25519',
		     sbvarsign_test_script,
		     args: [ 'ML-DSA65-ED25519',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool ML-DSA44-ED25519',
		     sbvarsign_test_script,
		     args: [ 'ML-DSA44-ED25519',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('Secure boot sbvarsign tool SLH-DSA-SHAKE-128F',
		     sbvarsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-128F',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool SLH-DSA-SHAKE-128S',
		     sbvarsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-128S',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool SLH-DSA-SHAKE-192F',
		     sbvarsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-192F',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool SLH-DSA-SHAKE-192S',
		     sbvarsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-192S',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool SLH-DSA-SHAKE-256F',
		     sbvarsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-256F',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbvarsign tool SLH-DSA-SHAKE-256S',
		     sbvarsign_test_script,
		     args: [ 'SLH-DSA-SHAKE-256S',
			     lc_x509_generator.full_path(),
			     sbvarsign.full_path()
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		if get_option('sha2-256').enabled()
			test('Secure boot sbsiglist tool',
			     sbsiglist_test_script,
			     args: [ sbsiglist.full_path(),
				     sha256sum.full_path()
				   ],
			     timeout: 300, suite: regression,
			     should_fail: fips140_negative_expect_fail)
		endif

		test('Secure boot sbattach tool ML-DSA87-ED448',
		     sbattach_test_script,
		     args: [ 'ML-DSA87-ED448',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbattach tool ML-DSA65-ED25519',
		     sbattach_test_script,
		     args: [ 'ML-DSA65-ED25519',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbattach tool ML-DSA44-ED25519',
		     sbattach_test_script,
		     args: [ 'ML-DSA44-ED25519',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)

		test('Secure boot sbattach tool SLH-DSA-SHAKE-128F',
		     sbattach_test_script,
		     args: [ 'SLH-DSA-SHAKE-128F',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbattach tool SLH-DSA-SHAKE-128S',
		     sbattach_test_script,
		     args: [ 'SLH-DSA-SHAKE-128S',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbattach tool SLH-DSA-SHAKE-192F',
		     sbattach_test_script,
		     args: [ 'SLH-DSA-SHAKE-192F',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbattach tool SLH-DSA-SHAKE-192S',
		     sbattach_test_script,
		     args: [ 'SLH-DSA-SHAKE-192S',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbattach tool SLH-DSA-SHAKE-256F',
		     sbattach_test_script,
		     args: [ 'SLH-DSA-SHAKE-256F',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
		test('Secure boot sbattach tool SLH-DSA-SHAKE-256S',
		     sbattach_test_script,
		     args: [ 'SLH-DSA-SHAKE-256S',
			     lc_x509_generator.full_path(),
			     sbsign.full_path(),
			     sbattach.full_path(),
			     efi_test_file
			   ],
		     timeout: 300, suite: regression,
		     should_fail: fips140_negative_expect_fail)
	endif
endif
