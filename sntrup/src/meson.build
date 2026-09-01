if sntrup_enabled == true

	# These files are compiled once
	src += files([
		'decode_int16.c',
		'encode_int16.c',
		'sntrup_kem_api.c',
		'sort_int32.c',
		'sort_uint32.c',
	])

	# These files are compiled once per parameter size
	sntrup_ref_src = files([
		'core_invsntrup.c',
		'core_inv3sntrup.c',
		'core_mult3sntrup.c',
		'core_multsntrup.c',
		'core_scale3sntrup.c',
		'core_weightsntrup.c',
		'core_wforcesntrup.c',
		'decode_x3.c',
		'decode_xint16.c',
		'decode_xint32.c',
		'encode_x3.c',
		'encode_xfreeze.c',
		'encode_xint16.c',
		'sntrup_kem.c',
		'verify.c'
	])

	if get_option('sntrup_1277').enabled()
		sntrup_1277_files = sntrup_ref_src
		subdir('1277')

		leancrypto_sntrup_1277_lib = static_library(
			'leancrypto_sntrup_1277_lib', [sntrup_1277_files],
			include_directories :
			[include_dirs, include_internal_dirs, '1277'], )
			leancrypto_support_libs += leancrypto_sntrup_1277_lib
	endif

	if get_option('sntrup_1013').enabled()
		sntrup_1013_files = sntrup_ref_src
		subdir('1013')

		leancrypto_sntrup_1013_lib = static_library(
			'leancrypto_sntrup_1013_lib', [sntrup_1013_files],
			include_directories :
			[include_dirs, include_internal_dirs, '1013'], )
			leancrypto_support_libs += leancrypto_sntrup_1013_lib
	endif

	if get_option('sntrup_953').enabled()
		sntrup_953_files = sntrup_ref_src
		subdir('953')

		leancrypto_sntrup_953_lib = static_library(
			'leancrypto_sntrup_953_lib', [sntrup_953_files],
			include_directories :
			[include_dirs, include_internal_dirs, '953'], )
			leancrypto_support_libs += leancrypto_sntrup_953_lib
	endif

	if get_option('sntrup_857').enabled()
		sntrup_857_files = sntrup_ref_src
		subdir('857')

		leancrypto_sntrup_857_lib = static_library(
			'leancrypto_sntrup_857_lib', [sntrup_857_files],
			include_directories :
			[include_dirs, include_internal_dirs, '857'], )
			leancrypto_support_libs += leancrypto_sntrup_857_lib
	endif

	if get_option('sntrup_761').enabled()
		sntrup_761_files = sntrup_ref_src
		subdir('761')

		leancrypto_sntrup_761_lib = static_library(
			'leancrypto_sntrup_761_lib', [sntrup_761_files],
			include_directories :
			[include_dirs, include_internal_dirs, '761'], )
			leancrypto_support_libs += leancrypto_sntrup_761_lib
	endif

endif
