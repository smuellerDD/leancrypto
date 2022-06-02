# for i in $(ls *.c | sort); do echo "'$i',"; done
if get_option('hotp').enabled()
	src += files([ 'hotp.c' ])
endif

if get_option('totp').enabled()
	src += files([ 'totp.c' ])
endif
