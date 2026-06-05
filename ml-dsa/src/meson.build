# for i in $(ls *.c | sort); do echo "'$i',"; done

# Files compiled only once
if (dilithium_enabled)
	src += files([
		'dilithium_common_api.c',
		'dilithium_keygen_api.c',
		'dilithium_siggen_api.c',
		'dilithium_sigver_api.c',
		'dilithium_ntt.c',
		'dilithium_poly.c',
		'dilithium_rounding.c',
		'dilithium_zetas.c'
	])
endif

# Files which are compiled for each Dilithium implementation separately
dilithium_c = files([
	'dilithium_poly_type.c',
	'dilithium_rounding_type.c',
	'dilithium_selftest.c',
	'dilithium_signature_keygen_c.c',
	'dilithium_signature_siggen_c.c',
	'dilithium_signature_sigver_c.c',
	'dilithium_signature_helper.c',
])

if get_option('dilithium_ed25519').enabled()
	dilithium_c += files ([
		'dilithium_ed25519_signature_common.c',
		'dilithium_ed25519_signature_keygen.c',
		'dilithium_ed25519_signature_siggen.c',
		'dilithium_ed25519_signature_sigver.c',
	])
endif

if get_option('dilithium_ed448').enabled()
	dilithium_c += files ([
		'dilithium_ed448_signature_common.c',
		'dilithium_ed448_signature_keygen.c',
		'dilithium_ed448_signature_siggen.c',
		'dilithium_ed448_signature_sigver.c',
	])
endif

if (dilithium_enabled)
	if (x86_64_asm)
		subdir('avx2')
	elif (arm64_asm)
		subdir('armv8')
	# 32 bit ARM processor and GCC
	elif (arm32_neon_asm)
		subdir('armv7')
	elif (riscv64_asm)
		subdir('riscv64')
	endif
endif

if get_option('dilithium_87').enabled()
	dilithium_87_files = dilithium_c

	if (x86_64_asm)
		dilithium_87_files += files([
			'avx2/dilithium_signature_keygen_api_avx2.c',
			'avx2/dilithium_signature_siggen_api_avx2.c',
			'avx2/dilithium_signature_sigver_api_avx2.c'
		])
	elif (arm64_asm)
		dilithium_87_files += files([
			'armv8/dilithium_signature_keygen_api_armv8.c',
			'armv8/dilithium_signature_siggen_api_armv8.c',
			'armv8/dilithium_signature_sigver_api_armv8.c',
		])
	elif (arm32_neon_asm)
		dilithium_87_files += files([
			'armv7/dilithium_signature_keygen_api_armv7.c',
			'armv7/dilithium_signature_siggen_api_armv7.c',
			'armv7/dilithium_signature_sigver_api_armv7.c'
		])
	elif (riscv64_asm)
		dilithium_87_files += files([
			'riscv64/dilithium_signature_keygen_api_riscv64.c',
			'riscv64/dilithium_signature_siggen_api_riscv64.c',
			'riscv64/dilithium_signature_sigver_api_riscv64.c'
		])
	else
		dilithium_87_files += files([
			'dilithium_signature_keygen_api_c.c',
			'dilithium_signature_siggen_api_c.c',
			'dilithium_signature_sigver_api_c.c',
		])
	endif

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

	if (x86_64_asm)
		dilithium_65_files += files([
			'avx2/dilithium_signature_keygen_api_avx2.c',
			'avx2/dilithium_signature_siggen_api_avx2.c',
			'avx2/dilithium_signature_sigver_api_avx2.c'
		])
	elif (arm64_asm)
		dilithium_65_files += files([
			'armv8/dilithium_signature_keygen_api_armv8.c',
			'armv8/dilithium_signature_siggen_api_armv8.c',
			'armv8/dilithium_signature_sigver_api_armv8.c'
		])
	elif (arm32_neon_asm)
		dilithium_65_files += files([
			'armv7/dilithium_signature_keygen_api_armv7.c',
			'armv7/dilithium_signature_siggen_api_armv7.c',
			'armv7/dilithium_signature_sigver_api_armv7.c'
		])
	elif (riscv64_asm)
		dilithium_65_files += files([
			'riscv64/dilithium_signature_keygen_api_riscv64.c',
			'riscv64/dilithium_signature_siggen_api_riscv64.c',
			'riscv64/dilithium_signature_sigver_api_riscv64.c'
		])
	else
		dilithium_65_files += files([
			'dilithium_signature_keygen_api_c.c',
			'dilithium_signature_siggen_api_c.c',
			'dilithium_signature_sigver_api_c.c',
		])
	endif

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

	if (riscv64_asm)
		dilithium_44_files += files([
			'riscv64/dilithium_signature_keygen_api_riscv64.c',
			'riscv64/dilithium_signature_siggen_api_riscv64.c',
			'riscv64/dilithium_signature_sigver_api_riscv64.c'
		])
	else
		dilithium_44_files += files([
			'dilithium_signature_keygen_api_c.c',
			'dilithium_signature_siggen_api_c.c',
			'dilithium_signature_sigver_api_c.c',
		])
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
