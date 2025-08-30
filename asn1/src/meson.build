# for i in $(ls *.c | sort); do echo "'$i',"; done

x509_common_support = 0

if get_option('x509_parser').enabled()
	x509_common_support = 1

	include_files += files([
		'../api/lc_x509_parser.h'
	])

	src_fips += files([
		'asn1_decoder.c',
		'x509_cert_parser.c',
		'x509_cert_parser_get_data.c',
		'x509_policies.c',
		'x509_public_key.c',
	])
endif

if get_option('x509_generator').enabled()
	x509_common_support = 1

	include_files += files([
		'../api/lc_x509_generator.h'
	])

	src_fips += files([
		'asn1_encoder.c',
		'asn1_encoder_helper.c',
		'asn1_encoder_small.c',
		'x509_cert_generator.c',
		'x509_cert_generator_set_data.c'
	])
else
	if get_option('x509_parser').enabled()
		src_fips += files([
			'x509_cert_generator_null.c'
		])
	endif
endif

if x509_common_support == 1
	asymmetric_algo = 0

	include_files += files([
		'../api/lc_asn1.h',
		'../api/lc_x509_common.h'
	])

	src_fips += files([
		'asn1_common.c',
		'asym_key.c',
		'asymmetric_type.c',
		'gmtime.c',
		'oid_registry.c',
		'x509_algorithm_mapper.c',

		'x509_asn1.c',
		'x509_akid_asn1.c',
		'x509_basic_constraints_asn1.c',
		'x509_eku_asn1.c',
		'x509_keyusage_asn1.c',
		'x509_mldsa_privkey_asn1.c',
		'x509_san_asn1.c',
		'x509_skid_asn1.c',
		'x509_slhdsa_privkey_asn1.c'
	])

	if (get_option('sphincs_shake_256s').enabled() or
	    get_option('sphincs_shake_256f').enabled() or
	    get_option('sphincs_shake_192s').enabled() or
	    get_option('sphincs_shake_192f').enabled() or
	    get_option('sphincs_shake_128s').enabled() or
	    get_option('sphincs_shake_128f').enabled())
		src_fips += files([ 'asym_key_sphincs.c' ])
		asymmetric_algo += 1
	else
		src_fips += files([ 'asym_key_sphincs_null.c' ])
	endif

	if (get_option('dilithium_87').enabled() or
	    get_option('dilithium_65').enabled() or
	    get_option('dilithium_44').enabled())
		src_fips += files([ 'asym_key_dilithium.c' ])
		asymmetric_algo += 1
	else
		src_fips += files([ 'asym_key_dilithium_null.c' ])
	endif

	if get_option('dilithium_ed25519').enabled()
		src_fips += files([
			'asym_key_dilithium_ed25519.c',
			'x509_mldsa_ed25519_privkey_asn1.c'
			])
		asymmetric_algo += 1
	else
		src_fips += files([ 'asym_key_dilithium_ed25519_null.c' ])
	endif

	if get_option('dilithium_ed448').enabled()
		src_fips += files([
			'asym_key_dilithium_ed448.c',
			'x509_mldsa_ed448_privkey_asn1.c'
			])
		asymmetric_algo += 1
	else
		src_fips += files([ 'asym_key_dilithium_ed448_null.c' ])
	endif

	if (asymmetric_algo == 0)
		error('X.509 parser without the presence of any asymmetric signature schema is useless')
	endif
endif

if get_option('pkcs7_parser').enabled()
	include_files += files([
		'../api/lc_pkcs7_common.h',
		'../api/lc_pkcs7_parser.h',
	])

	src_fips += files([
		'pkcs7_memory.c',
		'pkcs7_parser.c',
		'pkcs7_trust.c',
		'pkcs7_verify.c',

		'pkcs7_asn1.c',
		'pkcs7_aa_asn1.c',
	])
endif

if get_option('pkcs7_generator').enabled()
	include_files += files([
		'../api/lc_pkcs7_generator.h',
	])

	src_fips += files([
		'pkcs7_generator.c',
		'pkcs7_generator_set_data.c',
	])
else
	if get_option('pkcs7_parser').enabled()
		src_fips += files([
			'pkcs7_generator_null.c'
		])
	endif
endif

# Enable the ASN.1 compiler if one or more of the *.asn1 files were
# changed and need to be converted into C / H files
if get_option('efi').disabled()
	asn1_compiler_enabled = true
else
	asn1_compiler_enabled = false
endif

if (asn1_compiler_enabled)
	asn1_compiler_files = files([
		'asn1_compiler.c'
	])

	asn1_compiler = executable('asn1_compiler',
		[ asn1_compiler_files ],
		include_directories: [ include_internal_dirs ],
	)
endif
