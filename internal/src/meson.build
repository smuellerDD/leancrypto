# for i in $(ls *.c | sort); do echo "'$i',"; done
src_fips += files([
	'compare.c',
	'fips_mode.c',
	'leancrypto_init.c',
	'left_encode.c',
	'memcpy_secure_c.c',
	'null_buffer.c',
	'status_api.c',
	'status_algorithms.c'
])

if fips_checker_enabled
	src_fips += files([
		'fips_integrity_check.c',
	])
endif

if get_option('efi').disabled()
	internal_src += files([
		'binhexbin.c'
	])
	src_fips += files([
		'status.c'
	])
endif

if get_option('efi').enabled()
	src_fips += files([ 'memory_support_efi.c' ])
elif ((host_machine.system() == 'linux') and
      (host_machine.cpu_family() != 'x86'))
	src_fips += files([ 'memory_support_linux.c' ])
else
	src_fips += files([ 'memory_support.c' ])
endif

# FIPS 140 Integrity check: The integrity checker is adopted for ELF.
if (host_machine.system() == 'linux' and
    get_option('efi').disabled() and
    build_shared)
	src_fips_wrapper += files([
		'fips_integrity_checker_elf.c'
	])
else
	# Catchall for all other environments
	src_fips += files([
		'fips_integrity_checker_none.c'
	])
endif

if (dilithium_enabled or
    sphincs_enabled)
	src_fips += files([
		'signature_domain_separation.c',
	])
endif

# The memcmp_secure_avx2 code is disabled, because the compilation with AVX2
# flags causes the code to SIGILL on non-AVX2 environments. Considering that
# memcmp is not used in time critical code paths, we do not actually need
# the performance kick from AVX2.
# if (x86_64_asm)
# 	memcmp_secure_avx2 = files([ 'memcmp_secure_avx2.c' ])
# 	leancrypto_memcmp_secure_avx2_lib = static_library(
# 		'leancrypto_memcmp_secure_avx2_lib',
# 		[ memcmp_secure_avx2 ],
# 		include_directories: [
# 			include_dirs,
# 			include_internal_dirs
# 		],
# 		c_args: cc_avx2_args
# 	)
# 	leancrypto_support_libs_fips += leancrypto_memcmp_secure_avx2_lib
# endif
src_fips += files([ 'memcmp_secure_c.c' ])

include_files += files([
	'../api/ext_headers.h',
	'../api/lc_init.h',
	'../api/lc_memcmp_secure.h',
	'../api/lc_memcpy_secure.h',
	'../api/lc_memset_secure.h',
	'../api/lc_status.h'
	])

c_compiler = meson.get_compiler('c')
if (host_machine.cpu_family() == 'x86_64')
	src_fips += files([ 'cpufeatures_x86.c' ])
elif (arm64_neon_gcc_asm or arm64_asm)
	if (c_compiler.check_header('sys/auxv.h') and
	    get_option('efi').disabled())
		src_fips += files([ 'cpufeatures_arm64_auxv.c' ])
	else
		src_fips += files([ 'cpufeatures_arm64_native.c' ])
	endif
elif (arm32_neon_asm and c_compiler.check_header('sys/auxv.h'))
	src_fips += files([ 'cpufeatures_arm32.c' ])
elif (riscv32_asm or riscv64_asm or riscv32_gcc_asm or riscv64_gcc_asm)
	if (c_compiler.check_header('sys/auxv.h'))
		src_fips += files([ 'cpufeatures_riscv_auxv.c' ])
	else
		src_fips += files([ 'cpufeatures_riscv_native.c' ])
	endif
else
	src_fips += files([ 'cpufeatures_none.c' ])
endif

if secure_execution_linux
	src_fips += files([ 'secure_execution_linux.c' ])
endif
