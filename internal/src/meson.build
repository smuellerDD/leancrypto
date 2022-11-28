# for i in $(ls *.c | sort); do echo "'$i',"; done
internal_src = files([
	'binhexbin.c',
	'left_encode.c',
	'memcmp_secure.c',
	'memory_support.c',
	'null_buffer.c',
	'status.c'
])

include_files += files([
	'../api/ext_headers.h',
	'../api/memset_secure.h',
	'../api/lc_status.h'
	])

if (build_machine.cpu_family() == 'x86_64')
	src += files([ 'cpufeatures_x86.c' ])
else
	src += files([ 'cpufeatures_none.c' ])
endif
