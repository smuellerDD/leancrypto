# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('hotp').enabled()
	src += files([ 'hotp.c' ])
	include_files += files([ '../api/lc_hotp.h' ])
endif

if get_option('totp').enabled()
	src += files([ 'totp.c' ])
	include_files += files([ '../api/lc_totp.h' ])
endif
