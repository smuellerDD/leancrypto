# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('chacha20_drng').enabled()
	src += files([ 'chacha20_drng.c' ])
endif

if get_option('kmac_drng').enabled()
	src += files([ 'kmac_drng.c' ])
endif
