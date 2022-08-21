# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_sym = 0
lc_aes = 0

if get_option('chacha20').enabled()
	src += files([ 'chacha20.c' ])
	include_files += files([ '../api/lc_chacha20.h' ])
	lc_sym = 1
endif

if get_option('aes_block').enabled()
	src += files([ 'aes_block.c' ])
	lc_aes = 1
endif

if get_option('aes_ecb').enabled()
	src += files([ 'aes_ecb.c' ])
	lc_aes = 1
endif

if get_option('aes_cbc').enabled()
	src += files([ 'aes_cbc.c' ])
	lc_aes = 1
endif

if get_option('aes_ctr').enabled()
	src += files([ 'aes_ctr.c' ])
	lc_aes = 1
endif

if (lc_aes == 1)
	src += files([ 'aes.c' ])
	include_files += files([ '../api/lc_aes.h' ])
	lc_sym = 1
endif

if (lc_sym == 1)
	src += files([ 'sym.c' ])
	include_files += files([ '../api/lc_sym.h' ])
endif
