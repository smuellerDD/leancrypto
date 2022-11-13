# for i in $(ls *.c | sort); do echo "'$i',"; done
internal_src = files([
	'binhexbin.c',
	'left_encode.c',
	'memcmp_secure.c',
	'null_buffer.c'
])

include_files += files([
	'../api/ext_headers.h',
	'../api/memset_secure.h'
	])
