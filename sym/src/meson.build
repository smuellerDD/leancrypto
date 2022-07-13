# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_sym = 0

if get_option('chacha20').enabled()
	src += files([ 'chacha20.c' ])
	lc_sym = 1
endif

if (lc_sym == 1)
	include_files += files([ '../api/lc_sym.h' ])
endif
