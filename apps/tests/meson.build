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
		test('X.509 Generator Root-CA ML-DSA87',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA87' ],
		     suite: regression)
		test('X.509 Generator Root-CA ML-DSA65',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA65' ],
		     suite: regression)
		test('X.509 Generator Root-CA ML-DSA44',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA44' ],
		     suite: regression)

		test('X.509 Generator Root-CA SLH-DSA-SHAKE-256S',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-256S' ],
		     timeout: 600, suite: regression)
		test('X.509 Generator Root-CA SLH-DSA-SHAKE-256F',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-256F' ],
		     timeout: 600, suite: regression)
		test('X.509 Generator Root-CA SLH-DSA-SHAKE-192S',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-192S' ],
		     timeout: 600, suite: regression)
		test('X.509 Generator Root-CASLH-DSA-SHAKE-192F',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-192F' ],
		     timeout: 600, suite: regression)
		test('X.509 Generator Root-CA SLH-DSA-SHAKE-128S',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-128S' ],
		     timeout: 600, suite: regression)
		test('X.509 Generator Root-CA SLH-DSA-SHAKE-128F',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'SLH-DSA-SHAKE-128F' ],
		     timeout: 600, suite: regression)

		test('X.509 Generator Root-CA ML-DSA65-ED25519',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA65-ED25519' ],
		     suite: regression)
		test('X.509 Generator Root-CA ML-DSA44-ED25519',
		     lc_x509_generator,
		     args: [ x509_rootca_args, '--create-keypair', 'ML-DSA44-ED25519' ],
		     suite: regression)

		test('X.509 Generator Int-CA ML-DSA87',
		     lc_x509_generator,
		     args: [ x509_int1_ca_args, '--create-keypair', 'ML-DSA87' ],
		     suite: regression)
		test('X.509 Generator Leaf ML-DSA87',
		     lc_x509_generator,
		     args: [ x509_leaf_args, '--create-keypair', 'ML-DSA87' ],
		     suite: regression)

	endif

endif
