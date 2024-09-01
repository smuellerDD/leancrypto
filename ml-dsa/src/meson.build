# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (get_option('dilithium_87').enabled() or get_option('dilithium_65').enabled() or get_option('dilithium_44').enabled())
	src += files([
		'dilithium_domain_separation.c',
		'dilithium_signature_helper.c',
		'dilithium_zetas.c'
	])
endif

# Files which are compiled for each Dilithium implementation separately
dilithium_c = files([
	'dilithium_signature_c.c',
	'dilithium_ntt.c',
	'dilithium_poly.c',
	'dilithium_rounding.c',
	'dilithium_selftest.c'
])

if get_option('dilithium_debug').enabled()
	dilithium_c += files ([ 'dilithium_debug.c', ])
endif

if get_option('dilithium_ed25519').enabled()
	dilithium_c += files ([
		'dilithium_ed25519_signature.c',
	])
endif

dilithium_api_c = 0
if (x86_64_asm)
	subdir('avx2')
elif (arm64_asm)
	subdir('armv8')
# 32 bit ARM processor and GCC
elif (arm32_neon_asm)
	subdir('armv7')
else
	dilithium_api_c = 1
	dilithium_c += files([
		'dilithium_signature_api_c.c'
	])
endif

if get_option('dilithium_87').enabled()
	dilithium_87_files = dilithium_c

	leancrypto_dilithium_87_c_lib = static_library(
		'leancrypto_dilithium_87_c_lib',
		[ dilithium_87_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
	)
	leancrypto_support_libs += leancrypto_dilithium_87_c_lib
endif

if get_option('dilithium_65').enabled()
	dilithium_65_files = dilithium_c

	leancrypto_dilithium_65_c_lib = static_library(
		'leancrypto_dilithium_65_c_lib',
		[ dilithium_65_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_DILITHIUM_TYPE_65'
	)
	leancrypto_support_libs += leancrypto_dilithium_65_c_lib
endif

if get_option('dilithium_44').enabled()
	dilithium_44_files = dilithium_c

	if (dilithium_api_c == 0)
		dilithium_44_files += files([ 'dilithium_signature_api_c.c' ])
	endif

	leancrypto_dilithium_44_c_lib = static_library(
		'leancrypto_dilithium_44_c_lib',
		[ dilithium_44_files ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args : '-DLC_DILITHIUM_TYPE_44'
	)
	leancrypto_support_libs += leancrypto_dilithium_44_c_lib
endif
