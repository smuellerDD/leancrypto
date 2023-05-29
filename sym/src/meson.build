# for i in $(ls *.c | sort); do echo "'$i',"; done

lc_sym = 0
lc_aes = 0
lc_aesni_asm = 0
lc_block = 1

if get_option('chacha20').enabled()
	src += files([ 'chacha20.c' ])
	include_files += files([ '../api/lc_chacha20.h' ])
	lc_sym = 1
endif

if get_option('aes_ecb').enabled()
	src += files([ 'aes_ecb.c' ])
	lc_aes = 1
endif

if get_option('aes_cbc').enabled()
	src += files([ 'aes_cbc.c', 'mode_cbc.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_cbc_aesni.c' ])
	else
		src += files([ 'aes_cbc_aesni_null.c' ])
	endif
endif

if get_option('aes_ctr').enabled()
	src += files([ 'aes_ctr.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_ctr_aesni.c' ])
	else
		src += files([ 'aes_ctr_aesni_null.c' ])
	endif
endif

if get_option('aes_kw').enabled()
	src += files([ 'aes_kw.c', 'mode_kw.c'])
	lc_aes = 1
	lc_block = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_kw_aesni.c' ])
	else
		src += files([ 'aes_kw_aesni_null.c' ])
	endif
endif

if (lc_block == 1)
	src += files([ 'aes_block.c' ])
	lc_aes = 1

	# AES-NI
	if (x86_64_asm)
		lc_aesni_asm = 1
		src += files([ 'aes_block_aesni.c' ])
	else
		src += files([ 'aes_block_aesni_null.c' ])
	endif
endif

if (lc_aesni_asm == 1)
	src += files([ 'asm/AESNI_x86_64/aes_aesni_x86_64.S' ])
endif

if (lc_aes == 1)
	src += files([ 'aes.c',
		       'aes_selector.c'
		     ])
	include_files += files([ '../api/lc_aes.h' ])
	lc_sym = 1
endif

if (lc_sym == 1)
	src += files([ 'sym.c' ])
	include_files += files([ '../api/lc_sym.h' ])
endif
