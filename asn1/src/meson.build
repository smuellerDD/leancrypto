# for i in $(ls *.c | sort); do echo "'$i',"; done

if get_option('x509').enabled()
	asymmetric_algo = 0

	include_files += files([
		'../api/lc_asn1.h',
		'../api/lc_x509.h'
	])

	src += files([
		'asn1_decoder.c',
		'asymmetric_type.c',
		'oid_registry.c',
		'public_key.c',
		'x509_cert_parser.c',
		'x509_policies.c',
		'x509_public_key.c',

		'x509.asn1.c',
		'x509_basic_constraints.asn1.c',
		'x509_akid.asn1.c',
		'x509_eku.asn1.c',
		'x509_keyusage.asn1.c',
		'x509_san.asn1.c',
		'x509_skid.asn1.c'
	])

	if (get_option('sphincs_shake_256s').enabled() or
	    get_option('sphincs_shake_256f').enabled() or
	    get_option('sphincs_shake_192s').enabled() or
	    get_option('sphincs_shake_192f').enabled() or
	    get_option('sphincs_shake_128s').enabled() or
	    get_option('sphincs_shake_128f').enabled())
		src += files([ 'public_key_sphincs.c' ])
		asymmetric_algo += 1
	else
		src += files([ 'public_key_sphincs_null.c' ])
	endif

	if (get_option('dilithium_87').enabled() or
	    get_option('dilithium_65').enabled() or
	    get_option('dilithium_44').enabled())
		src += files([ 'public_key_dilithium.c' ])
		asymmetric_algo += 1
	else
		src += files([ 'public_key_dilithium_null.c' ])
	endif

	if get_option('dilithium_ed25519').enabled()
		src += files([ 'public_key_dilithium_ed25519.c' ])
		asymmetric_algo += 1
	else
		src += files([ 'public_key_dilithium_ed25519_null.c' ])
	endif

	if (asymmetric_algo == 0)
		error('X.509 parser without the presence of any asymmetric signature schema is useless')
	endif

	# Enable the ASN.1 compiler if one or more of the *.asn1 files were
	# changed and need to be converted into C / H files
	asn1_compiler_enabled = true
	if (asn1_compiler_enabled)
		asn1_compiler_files = files([
			'asn1_compiler.c'
		])

		asn1_compiler = executable('asn1_compiler',
			[ asn1_compiler_files ],
			include_directories: [ include_internal_dirs ],
		)
	endif
endif

if get_option('pkcs7').enabled()
	include_files += files([
		'../api/lc_pkcs7.h',
	])

	src += files([
		'pkcs7_parser.c',
		'pkcs7_verify.c',

		'pkcs7.asn1.c',
	])
endif
