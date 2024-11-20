hasher_test_script = find_program('hasher-test.sh', required: true)

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

x509_int1_ca_args = [
	'--keyusage', 'digitalSignature',
	'--keyusage', 'keyEncipherment',
	'--keyusage', 'keyCertSign',
	'--keyusage', 'critical',
	'--ca',
	'--valid-from', '1729527728',
	'--valid-to', '2044210606',
	'--subject-cn', 'leancrypto test int1',
	'--subject-ou', 'leancrypto test OU',
	'--subject-o', 'leancrypto',
	'--subject-st', 'Saxony',
	'--subject-c', 'DE',
	'--serial', '0203030405060708',
	'--skid', '0b0c0d0e0f0001',
	'--noout',
	'--print',
	'--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
	'--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.privkey',
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
	'--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_int2.der',
	'--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_int2.privkey',
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
	'--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-128f_leaf.der',
	'--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-128f_leaf.privkey',
	'-i', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
	'--print',
	'--noout'
	]

pkcs7_arg_int1 = [
	'--x509-cert',  meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-256f_int1.der'
	]

pkcs7_arg_int2 = [
	'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-192f_int2.der'
	]

pkcs7_arg_ca = [
	'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-256s_cacert.der'
	]

pkcs7_arg_trust = [
	'--trust-anchor', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-256s_cacert.der'
	]
pkcs7_arg_other_trust = [
	'--trust-anchor', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der'
	]

# Apps use POSIX API that is not available on regular Windows
if (host_machine.system() != 'windows') and get_option('apps').enabled()
	if get_option('sha2-256').enabled()
		test('sha256sum', hasher_test_script,
		     args: [ sha256sum.full_path(), '/usr/bin/sha256sum' ],
		     suite: regression)
	endif

	if get_option('sha2-512').enabled()
		test('sha512sum', hasher_test_script,
		     args: [ sha512sum.full_path(), '/usr/bin/sha512sum' ],
		     suite: regression)
	endif

	if get_option('sha3').enabled()
		test('sha3-256sum', hasher_test_script,
		     args: [ sha3_256sum.full_path(), '/usr/bin/sha3-256sum' ],
		     suite: regression)
		test('sha3-384sum', hasher_test_script,
		     args: [ sha3_384sum.full_path(), '/usr/bin/sha3-384sum' ],
		     suite: regression)
		test('sha3-512sum', hasher_test_script,
		     args: [ sha3_512sum.full_path(), '/usr/bin/sha3-512sum' ],
		     suite: regression)
	endif

	if get_option('x509_generator').enabled()
		test('X.509 Gen Root-CA ML-DSA87',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA87' ],
		     timeout: 300, suite: regression)
		test('X.509 Gen Root-CA ML-DSA65',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA65' ],
		     timeout: 300, suite: regression)
		test('X.509 Gen Root-CA ML-DSA44',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA44' ],
		     timeout: 300, suite: regression)

		test('X.509 Gen Root-CA SLH-DSA-SHAKE-256S',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-256S' ],
		     is_parallel: false, timeout: 600, suite: regression)
		test('X.509 Gen Root-CA SLH-DSA-SHAKE-256F',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-256F' ],
		     is_parallel: false, timeout: 600, suite: regression)
		test('X.509 Gen Root-CA SLH-DSA-SHAKE-192S',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-192S' ],
		     is_parallel: false, timeout: 600, suite: regression)
		test('X.509 Gen Root-CA SLH-DSA-SHAKE-192F',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-192F' ],
		     is_parallel: false, timeout: 600, suite: regression)
		test('X.509 Gen Root-CA SLH-DSA-SHAKE-128S',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-128S' ],
		     is_parallel: false, timeout: 600, suite: regression)
		test('X.509 Gen Root-CA SLH-DSA-SHAKE-128F',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-128F' ],
		     is_parallel: false, timeout: 600, suite: regression)

		test('X.509 Gen Root-CA ML-DSA65-ED25519',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA65-ED25519' ],
		     timeout: 300, suite: regression)
		test('X.509 Gen Root-CA ML-DSA44-ED25519',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA44-ED25519' ],
		     timeout: 300, suite: regression)

		test('X.509 Gen Int-CA ML-DSA87',
		     lc_x509_generator,
		     args: [ x509_int1_ca_args, '--create-keypair', 'ML-DSA87' ],
		     timeout: 300, suite: regression)
		test('X.509 Gen Leaf ML-DSA87',
		     lc_x509_generator,
		     args: [ x509_leaf_args, '--create-keypair', 'ML-DSA87' ],
		     timeout: 300, suite: regression)

	endif

	if get_option('pkcs7_generator').enabled()

		test('PKCS7 Gen with SLH-DSA 4-way cert chain',
			lc_pkcs7_generator,
			args: [ '--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-128f_leaf.der',
				'--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-128f_leaf.privkey',
				'-i', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
				'--print',
				'--noout',
				'--x509-cert',  meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-256f_int1.der',
				'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-192f_int2.der',
				'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-256s_cacert.der',
				'--trust-anchor', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-256s_cacert.der' ],
			is_parallel: false, timeout: 300, suite: regression)

		# SHA3-512 is default
		test('PKCS7 Gen with ML-DSA 4-way cert chain SHA3-512',
			lc_pkcs7_generator,
			args: [ '--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_leaf.der',
				'--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_leaf.privkey',
				'-i', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
				'--print',
				'--noout',
				'--x509-cert',  meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa65_int1.der',
				'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa44_int2.der',
				'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
				'--trust-anchor', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der' ],
			is_parallel: false, timeout: 300, suite: regression)

		if get_option('sha3').enabled()
			test('PKCS7 Gen with ML-DSA 4-way cert chain SHAKE256',
				lc_pkcs7_generator,
				args: [ '--md', 'SHAKE256',
					'--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_leaf.der',
					'--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_leaf.privkey',
					'-i', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
					'--print',
					'--noout',
					'--x509-cert',  meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa65_int1.der',
					'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa44_int2.der',
					'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
					'--trust-anchor', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der' ],
				is_parallel: false, timeout: 300,
				suite: regression)
		endif

		if get_option('sha2-512').enabled()
			test('PKCS7 Gen with ML-DSA 4-way cert chain SHA2-512',
			lc_pkcs7_generator,
				args: [ '--md', 'SHA2-512',
					'--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_leaf.der',
					'--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_leaf.privkey',
					'-i', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
					'--print',
					'--noout',
					'--x509-cert',  meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa65_int1.der',
					'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa44_int2.der',
					'--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
					'--trust-anchor', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der' ],
				is_parallel: false, timeout: 300,
				suite: regression)
		endif

		test('PKCS7 Gen with ML-DSA-ED25519 4-way cert chain',
		     lc_pkcs7_generator,
		     args: [ '--x509-signer', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-128s_leaf.der',
			     '--signer-sk-file', meson.project_source_root() + '/asn1/tests/testcerts/slh-dsa-shake-128s_leaf.privkey',
			     '-i', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_cacert.der',
			     '--print',
			     '--noout',
			     '--x509-cert',  meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa44-ed25519_int1.der',
			     '--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa87_int2.der',
			     '--x509-cert', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa65-ed25519_cacert.der',
			     '--trust-anchor', meson.project_source_root() + '/asn1/tests/testcerts/ml-dsa65-ed25519_cacert.der' ],
		     is_parallel: false, timeout: 300, suite: regression)

		# Trust-Store enabled with cert chain leading to CA
		test('PKCS7 Gen with valid Trust-Store',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2,
			     pkcs7_arg_ca,
			     pkcs7_arg_trust ],
		     is_parallel: false, timeout: 300, suite: regression)

		# Trust-Store enabled with cert chain leading to CA
		# Although certificate chain has no root CA, it is taken from
		# Trust Store
		test('PKCS7 Gen with valid Trust-Store 2',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2,
			     pkcs7_arg_trust ],
		     is_parallel: false, timeout: 300, suite: regression)

		# Trust-Store enabled with cert chain not leading to CA
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
		     is_parallel: false, timeout: 300, suite: regression)

		# Trust-Store disabled but with root CA cert
		test('PKCS7 Gen no root CA',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int1,
			     pkcs7_arg_int2 ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)

		# Missing intermediate
		test('PKCS7 Gen with missing intermediate',
		     lc_pkcs7_generator,
		     args: [ pkcs7_arg_signer,
			     pkcs7_arg_int2,
			     pkcs7_arg_ca,
			     pkcs7_arg_other_trust ],
		     is_parallel: false, timeout: 300, should_fail: true, suite: regression)
	endif
endif
