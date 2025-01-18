# for i in $(ls *.c | sort); do echo "'$i',"; done
internal_src += files([
	'compare.c',
	'left_encode.c',
	'memcpy_secure_c.c',
	'null_buffer.c',
	'signature_domain_separation.c',
])

if get_option('efi').disabled()
	internal_src += files([
		'binhexbin.c',
		'status.c'
	])
else
	internal_src += files([
		'leancrypto_init.c',
	])
endif

if get_option('efi').enabled()
	internal_src += files([ 'memory_support_efi.c' ])
elif host_machine.system() == 'linux'
	internal_src += files([ 'memory_support_linux.c' ])
else
	internal_src += files([ 'memory_support.c' ])
endif

if (x86_64_asm)
	memcmp_secure_avx2 = files([ 'memcmp_secure_avx2.c' ])
	leancrypto_memcmp_secure_avx2_lib = static_library(
		'leancrypto_memcmp_secure_avx2_lib',
		[ memcmp_secure_avx2 ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args: cc_avx2_args
	)
	leancrypto_support_libs_fips += leancrypto_memcmp_secure_avx2_lib
else
	src_fips += files([ 'memcmp_secure_c.c' ])
endif

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
	if (c_compiler.check_header('sys/auxv.h'))
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
