# for i in $(ls *.c | sort); do echo "'$i',"; done
internal_src = files([
	'binhexbin.c',
	'compare.c',
	'left_encode.c',
	'memory_support.c',
	'null_buffer.c',
	'status.c'
])

if (x86_64_asm)
	memcmp_secure_avx2 = files([ 'memcmp_secure_avx2.c' ])
	leancrypto_memcmp_secure_avx2_lib = static_library(
		'leancrypto_memcmp_secure_avx2_lib',
		[ memcmp_secure_avx2 ],
		include_directories: [
			include_dirs,
			include_internal_dirs
		],
		c_args: [
			'-mavx2',
			'-Wno-unused-command-line-argument'
		]
	)
	leancrypto_support_libs += leancrypto_memcmp_secure_avx2_lib
else
	src += files([ 'memcmp_secure_c.c' ])
endif

include_files += files([
	'../api/ext_headers.h',
	'../api/lc_memset_secure.h',
	'../api/lc_memory_support.h',
	'../api/lc_status.h'
	])

c_compiler = meson.get_compiler('c')
if (host_machine.cpu_family() == 'x86_64')
	src += files([ 'cpufeatures_x86.c' ])
elif ((arm64_neon_gcc_asm or arm64_asm) and
      c_compiler.check_header('sys/auxv.h'))
	src += files([ 'cpufeatures_arm64.c' ])
elif (arm32_neon_gcc_asm and c_compiler.check_header('sys/auxv.h'))
	src += files([ 'cpufeatures_arm32.c' ])
elif (riscv32_gcc_asm)
	src += files([ 'cpufeatures_riscv.c' ])
else
	src += files([ 'cpufeatures_none.c' ])
endif
