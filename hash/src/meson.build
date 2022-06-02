# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('sha2-256').enabled() or get_option('sha2-512').enabled() or get_option('sha3').enabled()
	src += files([ 'hash.c' ])
endif

if get_option('sha2-256').enabled()
	src += files([ 'sha256.c' ])
endif

if get_option('sha2-512').enabled()
	src += files([ 'sha512.c' ])
endif

if get_option('sha3').enabled()
	src += files([ 'cshake.c', 'sha3.c' ])
endif
